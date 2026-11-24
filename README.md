# Forwarding ROSA Control Plane Audit Logs to Microsoft Sentinel

Red Hat OpenShift Service on AWS (ROSA) with Hosted Control Planes (HCP) doesn't give you node-level
access to the control plane, so the classic on-prem pattern — running the OpenShift Logging Operator's
`ClusterLogForwarder` as a daemonset to tail the API server's audit log off disk — isn't available.
Instead, ROSA exposes a managed **control plane log forwarder** that ships logs to a destination
*you* own (Amazon CloudWatch and/or Amazon S3), outside the cluster and without using worker node
resources.

This article walks through one way to get those logs into Microsoft Sentinel: ROSA's control plane
log forwarder writes to S3, an AWS Lambda function (triggered by an SQS queue fed by S3 event
notifications) reshapes the audit events and pushes them into a Microsoft Sentinel custom table over
the Azure Monitor Logs Ingestion API.

It's close in spirit to [Forwarding and Monitoring ROSA HCP Control Plane Audit Logs with
Filebeat](https://cloud.redhat.com/experts/rosa/audit-logs-filebeat/), but swaps Filebeat/Elasticsearch
for a serverless Lambda and a Sentinel destination.

> Every command below was run end-to-end against a live ROSA HCP cluster and a Microsoft Sentinel
> workspace. Account IDs, cluster names, and resource identifiers are placeholders — substitute your
> own.

## Architecture

```
ROSA control plane  --->  S3 bucket  --->  S3 event notification  --->  SQS queue
 (managed log forwarder)   (your account)                                  |
                                                                            v
                                                                    AWS Lambda function
                                                                 (reads object, extracts
                                                                  audit.k8s.io/v1 events,
                                                                  calls Azure AD for a token)
                                                                            |
                                                                            v
                                                      Azure Monitor Logs Ingestion API (DCE + DCR)
                                                                            |
                                                                            v
                                                 Microsoft Sentinel custom table (ROSAControlPlaneAudit_CL)
```

Why this shape, and not the generic **Amazon Web Services S3** connector in Sentinel's data connector
gallery? That connector's built-in parsers only understand four source formats — VPC Flow Logs,
GuardDuty findings, CloudTrail, and CloudWatch Logs exported as headerless CSV/GZIP. ROSA's log
forwarder writes newline-free JSON arrays of structured container log records (not CSV), so none of
the built-in destination tables match. There's also an **Amazon Web Services S3 EKS** connector that
looks tempting given the Kubernetes-audit use case, but its CloudFormation templates and Lambda
transform are hard-wired to EKS's own audit-logging and CloudWatch subscription-filter APIs — they
don't apply to ROSA. A small custom Lambda plus a Sentinel **custom log table** (Data Collection Rule)
sidesteps both constraints and keeps the full original audit event available in Sentinel via a
`RawEvent` column.

## Part 1 — Enable the ROSA control plane log forwarder

### Prerequisites

- An AWS account with permission to create S3 buckets/policies.
- `rosa` and `aws` CLIs installed and authenticated against the cluster's owning OCM organization.
- At the time of writing, the public `rosa` CLI (checked at v1.2.53, "latest") does **not** yet expose
  a `create log-forwarder` subcommand or a `--log-fwd-config` flag for the new S3-and-CloudWatch,
  multi-log-group control plane log forwarder described in the
  [ROSA logging documentation](https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/logging/rosa-forwarding-control-plane-logs).
  The CLI only knows about the older, CloudWatch-only `--audit-log-arn` flag. The feature is live at
  the OCM API layer, though — `GET/POST /api/clusters_mgmt/v1/clusters/{cluster_id}/control_plane/log_forwarders` —
  so you can drive it directly with a bearer token until CLI support ships. Check `rosa create
  log-forwarder --help` first; if it exists for you, use it and skip the raw API calls below.

### 1.1 Decide which log groups you need

Call the log-forwarding catalog to see the available groups, their applications, and schema versions:

```bash
curl -s -H "Authorization: Bearer $(rosa token 2>/dev/null || jq -r .access_token ~/.config/ocm/ocm.json)" \
  https://api.openshift.com/api/clusters_mgmt/v1/log_forwarding/groups | jq .
```

Relevant groups for audit/security use cases:

| Group | Applications |
|---|---|
| `api` (v1.0) | `audit-webhook`, `kube-apiserver`, `oauth-openshift`, `openshift-apiserver`, `openshift-oauth-apiserver`, `packageserver`, `validation-webhook` |
| `authentication` (v1.0) | `ignition-server`, `konnectivity-agent` |
| `controller manager` (v1.1) | `kube-controller-manager`, `cluster-policy-controller`, and other control-plane operators |
| `scheduler` (v1.0) | `kube-scheduler` |

The actual Kubernetes `audit.k8s.io/v1` audit trail — the record of every API request, who made it,
and whether it was authorized — comes from the `api` group. `controller manager` and `scheduler` are
operational/component logs, not audit events; only pull those in if you have a specific troubleshooting
or compliance need, since they add volume without adding audit signal.

### 1.2 Create the destination S3 bucket

Per the docs, an S3 destination does **not** require a customer IAM role — only a bucket policy that
trusts Red Hat's managed `ROSA-CentralLogDistributionRole`. The only supported bucket encryption is
SSE-S3 (`AES256`); don't put a KMS-encrypted bucket here, the log forwarder's role has no `kms:Decrypt`
permission on your keys.

```bash
BUCKET="<your-bucket-name>"
REGION="<cluster-region>"

aws s3api create-bucket \
  --bucket "$BUCKET" \
  --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION"
```

```json
// s3-bucket-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCentralLogDistributionWrite",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::859037107838:role/ROSA-CentralLogDistributionRole-241c1a86"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::<your-bucket-name>/*",
      "Condition": {
        "StringEquals": { "s3:x-amz-acl": "bucket-owner-full-control" }
      }
    }
  ]
}
```

```bash
aws s3api put-bucket-policy --bucket "$BUCKET" --policy file://s3-bucket-policy.json
```

### 1.3 Create the log forwarder

Using the `rosa` CLI, once your version supports it:

```yaml
# log-fwd-config.yaml
s3:
  s3_config_bucket_name: "<your-bucket-name>"
  s3_config_bucket_prefix: "control-plane-logs"
groups:
  - "api"
  - "authentication"
```

```bash
rosa create log-forwarder -c <cluster-name> --log-fwd-config="log-fwd-config.yaml" -o yaml
```

Or, directly against the OCM API if your CLI predates the subcommand:

```bash
CLUSTER_ID="<ocm-internal-cluster-id>"   # rosa describe cluster -c <name> -o json | jq -r .id
TOKEN="$(jq -r .access_token ~/.config/ocm/ocm.json)"

curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "https://api.openshift.com/api/clusters_mgmt/v1/clusters/$CLUSTER_ID/control_plane/log_forwarders" \
  -d '{
        "s3": {
          "bucket_name": "<your-bucket-name>",
          "bucket_prefix": "control-plane-logs"
        },
        "groups": [
          { "id": "api", "version": "1.0" },
          { "id": "authentication", "version": "1.0" }
        ]
      }' | jq .
```

A successful response reports `"status": {"state": "ready", ...}` and lists every application that
got resolved from the requested groups. Objects typically start landing in S3 within a couple of
minutes — no cluster restart or pod disruption involved.

### 1.4 What actually lands in S3

Each object is a **gzip-compressed JSON array** of structured log records (Filebeat/Fluentd-style),
one array per collection interval per source pod — not newline-delimited JSON, and not CSV. Most
records carry the component's own stdout (e.g., `kube-apiserver`'s gRPC/controller chatter). The real
audit trail is in the records where `container_name == "audit-logs"`: a sidecar that streams the
apiserver's `audit.k8s.io/v1` log file to stdout, one JSON `Event` object per `message` field (as a
*string*, so it needs a second `json.loads`):

```json
{
  "application": "openshift-apiserver",
  "container_name": "audit-logs",
  "namespace": "ocm-production-<cluster-internal-id>",
  "pod_name": "openshift-apiserver-<hash>",
  "mc_cluster_id": "<management-cluster-id>",
  "timestamp": "2026-11-24T16:55:47.063Z",
  "message": "{\"kind\":\"Event\",\"apiVersion\":\"audit.k8s.io/v1\",\"level\":\"Metadata\",\"auditID\":\"5665e725-...\",\"stage\":\"ResponseComplete\",\"requestURI\":\"/metrics\",\"verb\":\"get\",\"user\":{\"username\":\"system:serviceaccount:hypershift:prometheus\",\"groups\":[\"kubernetes\",\"system:authenticated\"]},\"sourceIPs\":[\"10.128.112.33\"],\"userAgent\":\"Go-http-client/1.1\",\"responseStatus\":{\"code\":200},\"requestReceivedTimestamp\":\"2026-11-24T16:55:47.034Z\",\"stageTimestamp\":\"2026-11-24T16:55:47.063Z\",\"annotations\":{\"authorization.k8s.io/decision\":\"allow\",\"authorization.k8s.io/reason\":\"RBAC: allowed by ClusterRoleBinding ...\"}}"
}
```

This matters for anyone building a transform against this feed: filter on `container_name ==
"audit-logs"` first, *then* parse `message` as JSON and check `kind == "Event"`. Don't assume every
record in the object is an audit event.

## Part 2 — AWS side: SQS queue and Lambda

### 2.1 SQS queue fed by S3 event notifications

```bash
QUEUE_NAME="rosa-cplf-sentinel-sqs"
ACCOUNT_ID="<your-account-id>"
REGION="<your-region>"

QUEUE_URL=$(aws sqs create-queue --queue-name "$QUEUE_NAME" --region "$REGION" --query QueueUrl --output text)

cat > sqs-attrs.json <<EOF
{
  "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AllowS3SendMessage\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"s3.amazonaws.com\"},\"Action\":\"SQS:SendMessage\",\"Resource\":\"arn:aws:sqs:${REGION}:${ACCOUNT_ID}:${QUEUE_NAME}\",\"Condition\":{\"ArnEquals\":{\"aws:SourceArn\":\"arn:aws:s3:::${BUCKET}\"}}}]}",
  "VisibilityTimeout": "120"
}
EOF
aws sqs set-queue-attributes --queue-url "$QUEUE_URL" --attributes file://sqs-attrs.json
```

The visibility timeout (120s) must exceed the Lambda's configured timeout, or Lambda will refuse to
attach the event source mapping.

```bash
cat > notification.json <<EOF
{
  "QueueConfigurations": [{
    "Id": "rosa-cplf-to-sentinel-sqs",
    "QueueArn": "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:${QUEUE_NAME}",
    "Events": ["s3:ObjectCreated:*"],
    "Filter": { "Key": { "FilterRules": [{ "Name": "prefix", "Value": "control-plane-logs/" }] } }
  }]
}
EOF
aws s3api put-bucket-notification-configuration --bucket "$BUCKET" --notification-configuration file://notification.json
```

### 2.2 The Lambda function

```python
"""
ROSA control plane audit logs -> Microsoft Sentinel (custom table via Logs Ingestion API)
"""
import os, gzip, json, time, urllib.request, urllib.error, urllib.parse
import boto3

s3 = boto3.client("s3")

AAD_TENANT_ID = os.environ["AAD_TENANT_ID"]
AAD_CLIENT_ID = os.environ["AAD_CLIENT_ID"]
AAD_CLIENT_SECRET = os.environ["AAD_CLIENT_SECRET"]
DCE_INGESTION_ENDPOINT = os.environ["DCE_INGESTION_ENDPOINT"]
DCR_IMMUTABLE_ID = os.environ["DCR_IMMUTABLE_ID"]
DCR_STREAM_NAME = os.environ.get("DCR_STREAM_NAME", "Custom-ROSAControlPlaneAudit")

_token_cache = {"value": None, "expires_at": 0}

def _get_token():
    if _token_cache["value"] and time.time() < _token_cache["expires_at"] - 60:
        return _token_cache["value"]
    url = f"https://login.microsoftonline.com/{AAD_TENANT_ID}/oauth2/v2.0/token"
    body = urllib.parse.urlencode({
        "client_id": AAD_CLIENT_ID,
        "client_secret": AAD_CLIENT_SECRET,
        "scope": "https://monitor.azure.com/.default",
        "grant_type": "client_credentials",
    }).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=body, method="POST"), timeout=10) as resp:
        payload = json.loads(resp.read())
    _token_cache["value"] = payload["access_token"]
    _token_cache["expires_at"] = time.time() + int(payload.get("expires_in", 3600))
    return _token_cache["value"]

def _to_sentinel_record(wrapper_record, event):
    user, ann = event.get("user", {}) or {}, event.get("annotations", {}) or {}
    return {
        "TimeGenerated": event.get("stageTimestamp") or event.get("requestReceivedTimestamp"),
        "AuditID": event.get("auditID", ""),
        "Stage": event.get("stage", ""),
        "Verb": event.get("verb", ""),
        "RequestURI": event.get("requestURI", ""),
        "UserName": user.get("username", ""),
        "UserGroups": user.get("groups", []),
        "SourceIPs": event.get("sourceIPs", []),
        "UserAgent": event.get("userAgent", ""),
        "ResponseCode": (event.get("responseStatus") or {}).get("code", 0),
        "ObjectRef": event.get("objectRef", {}),
        "AuthorizationDecision": ann.get("authorization.k8s.io/decision", ""),
        "AuthorizationReason": ann.get("authorization.k8s.io/reason", ""),
        "SourceApplication": wrapper_record.get("application", ""),
        "ClusterId": wrapper_record.get("mc_cluster_id", ""),
        "RequestReceivedTime": event.get("requestReceivedTimestamp"),
        "StageTime": event.get("stageTimestamp"),
        "RawEvent": event,
    }

def _extract_audit_records(body_bytes):
    records = json.loads(gzip.decompress(body_bytes))
    out = []
    for r in records:
        if r.get("container_name") != "audit-logs":
            continue
        try:
            event = json.loads(r["message"])
        except (KeyError, json.JSONDecodeError):
            continue
        if event.get("kind") != "Event":
            continue
        out.append(_to_sentinel_record(r, event))
    return out

# The Logs Ingestion API rejects requests over 1 MiB; batch by serialized
# size (with headroom), not record count -- RawEvent payloads vary a lot.
MAX_BATCH_BYTES = 800_000

def _chunk_by_size(records):
    chunk, chunk_bytes = [], 0
    for r in records:
        size = len(json.dumps(r))
        if chunk and chunk_bytes + size > MAX_BATCH_BYTES:
            yield chunk
            chunk, chunk_bytes = [], 0
        chunk.append(r)
        chunk_bytes += size
    if chunk:
        yield chunk

def _post_batch(token, batch):
    url = f"{DCE_INGESTION_ENDPOINT}/dataCollectionRules/{DCR_IMMUTABLE_ID}/streams/{DCR_STREAM_NAME}?api-version=2023-01-01"
    req = urllib.request.Request(
        url, data=json.dumps(batch).encode(), method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Sentinel ingestion failed: {e.code} {e.read().decode()[:500]}")

def handler(event, context):
    token = _get_token()
    processed = 0
    for sqs_record in event["Records"]:
        body = json.loads(sqs_record["body"])
        for s3_event in body.get("Records", []):
            bucket = s3_event["s3"]["bucket"]["name"]
            key = urllib.parse.unquote_plus(s3_event["s3"]["object"]["key"])
            obj = s3.get_object(Bucket=bucket, Key=key)
            batch = _extract_audit_records(obj["Body"].read())
            if not batch:
                continue
            for chunk in _chunk_by_size(batch):
                _post_batch(token, chunk)
                processed += len(chunk)
    return {"processed": processed}
```

Deploy it and wire the SQS trigger:

```bash
zip lambda.zip lambda_function.py

aws iam create-role --role-name rosa-cplf-sentinel-lambda-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

# Scope these down in production -- see "Hardening" below.
aws iam attach-role-policy --role-name rosa-cplf-sentinel-lambda-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam attach-role-policy --role-name rosa-cplf-sentinel-lambda-role --policy-arn arn:aws:iam::aws:policy/AmazonSQSFullAccess
aws iam attach-role-policy --role-name rosa-cplf-sentinel-lambda-role --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

aws lambda create-function \
  --function-name rosa-cplf-to-sentinel \
  --runtime python3.12 \
  --role "arn:aws:iam::${ACCOUNT_ID}:role/rosa-cplf-sentinel-lambda-role" \
  --handler lambda_function.handler \
  --zip-file fileb://lambda.zip \
  --timeout 60 --memory-size 256 \
  --environment "Variables={AAD_TENANT_ID=<tenant-id>,AAD_CLIENT_ID=<client-id>,AAD_CLIENT_SECRET=<client-secret>,DCE_INGESTION_ENDPOINT=<dce-logs-ingestion-url>,DCR_IMMUTABLE_ID=<dcr-immutable-id>,DCR_STREAM_NAME=Custom-ROSAControlPlaneAudit}"

aws lambda create-event-source-mapping \
  --function-name rosa-cplf-to-sentinel \
  --event-source-arn "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:${QUEUE_NAME}" \
  --batch-size 5
```

## Part 3 — Azure side: Sentinel workspace, custom table, Data Collection Rule

### 3.1 Workspace and Sentinel onboarding

```bash
az monitor log-analytics workspace create -g <resource-group> -n <workspace-name> -l <location> --sku PerGB2018

az rest --method put \
  --url "https://management.azure.com/subscriptions/<sub-id>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01" \
  --body '{"properties":{"customerManagedKey": false}}'
```

### 3.2 Data Collection Endpoint

```bash
az monitor data-collection endpoint create -g <resource-group> -l <location> --name rosa-cplf-dce --public-network-access Enabled
```

Note the `logsIngestion.endpoint` value in the output — that's `DCE_INGESTION_ENDPOINT` for the Lambda.

### 3.3 Custom table

```bash
az monitor log-analytics workspace table create \
  --resource-group <resource-group> --workspace-name <workspace-name> \
  --name ROSAControlPlaneAudit_CL \
  --columns TimeGenerated=datetime AuditID=string Stage=string Verb=string RequestURI=string \
            UserName=string UserGroups=dynamic SourceIPs=dynamic UserAgent=string ResponseCode=int \
            ObjectRef=dynamic AuthorizationDecision=string AuthorizationReason=string \
            SourceApplication=string ClusterId=string RequestReceivedTime=datetime \
            StageTime=datetime RawEvent=dynamic
```

### 3.4 Data Collection Rule

The DCR declares the incoming stream schema and maps it to the custom table's `_CL` output stream:

```json
{
  "location": "<location>",
  "properties": {
    "dataCollectionEndpointId": "<dce-resource-id>",
    "streamDeclarations": {
      "Custom-ROSAControlPlaneAudit": {
        "columns": [
          { "name": "TimeGenerated", "type": "datetime" },
          { "name": "AuditID", "type": "string" },
          { "name": "Stage", "type": "string" },
          { "name": "Verb", "type": "string" },
          { "name": "RequestURI", "type": "string" },
          { "name": "UserName", "type": "string" },
          { "name": "UserGroups", "type": "dynamic" },
          { "name": "SourceIPs", "type": "dynamic" },
          { "name": "UserAgent", "type": "string" },
          { "name": "ResponseCode", "type": "int" },
          { "name": "ObjectRef", "type": "dynamic" },
          { "name": "AuthorizationDecision", "type": "string" },
          { "name": "AuthorizationReason", "type": "string" },
          { "name": "SourceApplication", "type": "string" },
          { "name": "ClusterId", "type": "string" },
          { "name": "RequestReceivedTime", "type": "datetime" },
          { "name": "StageTime", "type": "datetime" },
          { "name": "RawEvent", "type": "dynamic" }
        ]
      }
    },
    "destinations": {
      "logAnalytics": [{ "workspaceResourceId": "<workspace-resource-id>", "name": "rosaSentinelWorkspace" }]
    },
    "dataFlows": [{
      "streams": ["Custom-ROSAControlPlaneAudit"],
      "destinations": ["rosaSentinelWorkspace"],
      "outputStream": "Custom-ROSAControlPlaneAudit_CL"
    }]
  }
}
```

```bash
az rest --method put \
  --url "https://management.azure.com/subscriptions/<sub-id>/resourceGroups/<resource-group>/providers/Microsoft.Insights/dataCollectionRules/rosa-cplf-dcr?api-version=2023-03-11" \
  --body @dcr.json
```

Note the response's `properties.immutableId` (`dcr-...`) — that's `DCR_IMMUTABLE_ID` for the Lambda.

### 3.5 Authorize the Lambda's identity to publish

Create an Entra ID app registration (service principal) for the Lambda, then grant it the
**Monitoring Metrics Publisher** role scoped to the DCR — that's the only permission the Logs
Ingestion API requires:

```bash
az role assignment create \
  --assignee <lambda-app-client-id> \
  --role "Monitoring Metrics Publisher" \
  --scope "<dcr-resource-id>"
```

The Lambda authenticates with this app's client ID/secret via OAuth2 client-credentials grant against
`https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token`, requesting the
`https://monitor.azure.com/.default` scope, exactly as shown in `_get_token()` above.

## Part 4 — Verify

In Sentinel (or Log Analytics), confirm data is landing:

```kql
ROSAControlPlaneAudit_CL
| take 10
```

Useful hunting queries once data is flowing:

```kql
// Failed/denied requests
ROSAControlPlaneAudit_CL
| where ResponseCode >= 400 or AuthorizationDecision == "forbid"
| project TimeGenerated, UserName, Verb, RequestURI, ResponseCode, AuthorizationReason
| order by TimeGenerated desc
```

```kql
// Activity by source application and verb
ROSAControlPlaneAudit_CL
| summarize count() by SourceApplication, Verb
| order by count_ desc
```

```kql
// Who's creating/deleting/updating cluster-scoped objects
ROSAControlPlaneAudit_CL
| where Verb in ("create", "update", "delete", "patch")
| project TimeGenerated, UserName, Verb, ObjectRef, SourceIPs
| order by TimeGenerated desc
```

## Best practices and hardening

- **Scope the log groups to what you need.** `api` plus `authentication` covers the audit trail most
  compliance and threat-detection use cases care about. Adding `controller manager` or `scheduler`
  multiplies ingestion volume (and Sentinel ingestion cost) with operational noise, not audit signal —
  only add them if you have a specific need.
- **Least-privilege IAM for the Lambda.** The example above uses broad managed policies
  (`AmazonSQSFullAccess`, `AmazonS3ReadOnlyAccess`) to keep the walkthrough short. In production, scope
  the role to `sqs:ReceiveMessage`/`DeleteMessage`/`GetQueueAttributes` on the specific queue ARN and
  `s3:GetObject` on the specific bucket/prefix ARN only.
- **Don't store the Azure client secret as a plaintext Lambda environment variable long-term.** Pull it
  from AWS Secrets Manager (or Parameter Store with SecureString) at cold start instead, and rotate it
  on a schedule.
- **Batch by byte size, not record count.** The Logs Ingestion API caps requests at 1 MiB. A single S3
  object can hold anywhere from a handful to hundreds of audit events depending on cluster activity, and
  `RawEvent` payloads vary widely in size — a fixed record-count batch will eventually overflow the
  limit under load. Chunk by serialized size with headroom, as shown in `_chunk_by_size`.
- **Set an S3 lifecycle policy** on the bucket to transition old audit logs to Glacier or expire them
  per your retention requirement — this is your long-term compliance copy, independent of however long
  Sentinel retains the `_CL` table.
- **Monitor the pipeline itself.** Add a CloudWatch alarm on the Lambda's `Errors` metric and the SQS
  queue's `ApproximateAgeOfOldestMessage`, and set up a dead-letter queue on the event source mapping —
  a silent failure here means a silent gap in your audit trail.
- **Table retention vs. interactive query cost.** Consider setting `ROSAControlPlaneAudit_CL` to Basic
  log plan status in Sentinel if you mainly need long-term search/compliance rather than real-time
  analytics rules against it, since Analytics-tier ingestion is priced per GB and audit logs can be
  high-volume.

## Known gaps at time of writing

- The public `rosa` CLI doesn't yet expose the new S3-capable, multi-group control plane log forwarder
  as a subcommand (checked at v1.2.53). The OCM API already supports it
  (`/control_plane/log_forwarders`), so you can use it today via direct API calls; CLI support should
  follow.
- There's no generic "arbitrary JSON" destination table in Sentinel's native **Amazon Web Services S3**
  connector gallery entry — only VPC/GuardDuty/CloudTrail/CloudWatch-CSV. The custom-table/DCR approach
  here is the supported way to ingest a format Sentinel doesn't already know about.
