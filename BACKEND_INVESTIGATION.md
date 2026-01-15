# Backend Investigation: Cloud Agent Organization ID Not Being Used

## Problem Summary

When starting a cloud agent session from the VS Code extension, the session uses **personal credits** instead of **organization credits**, even though the extension correctly passes the `organizationId` in the request.

## Evidence from Extension Logs

The extension is correctly sending the organizationId:

```
[AgentManager] Provider state retrieved - kilocodeOrganizationId: 9d278969-5453-4ae3-a51f-a8d2274a7b56
[AgentManager] Preparing cloud agent session with githubRepo: Kilo-Org/kilocode, mode: code, model: claude-sonnet-4-20250514, organizationId: 9d278969-5453-4ae3-a51f-a8d2274a7b56
[AgentManager] Cloud session prepared: agent_921be6f5-1b63-4ef1-a8b1-d6bda3d8878f
[AgentManager] Redirecting to web app: https://app.kilo.ai/cloud/chat?sessionId=efd969c3-f424-4fad-85f8-700d33172047
```

## Request Details

### Endpoint

```
POST https://api.kilo.ai/api/cloud-agent/sessions/prepare
```

### Headers

```
Authorization: Bearer <kilocodeToken>
Content-Type: application/json
```

### Request Body

```json
{
	"githubRepo": "Kilo-Org/kilocode",
	"prompt": "hi",
	"mode": "code",
	"model": "claude-sonnet-4-20250514",
	"organizationId": "9d278969-5453-4ae3-a51f-a8d2274a7b56"
}
```

### Expected Response

```json
{
	"kiloSessionId": "efd969c3-f424-4fad-85f8-700d33172047",
	"cloudAgentSessionId": "agent_921be6f5-1b63-4ef1-a8b1-d6bda3d8878f"
}
```

## Files to Investigate

### 1. Backend Route Handler

**File:** `src/app/api/cloud-agent/sessions/prepare/route.ts`

This file receives the request and should:

1. Extract `input.organizationId` from the request body
2. Call `ensureOrganizationAccess()` if organizationId is present
3. Set `kilocodeOrganizationId = input.organizationId`
4. Pass `kilocodeOrganizationId` to the cloud-agent client's `prepareSession()`

**Questions to answer:**

- Is `input.organizationId` being correctly extracted from the request body?
- Is `kilocodeOrganizationId` being passed to `client.prepareSession()`?

### 2. Cloud Agent Client

**File:** `src/lib/cloud-agent/cloud-agent-client.ts`

The `PrepareSessionInput` type (line ~133) includes `kilocodeOrganizationId?: string`.

**Questions to answer:**

- Is the `prepareSession()` method correctly forwarding `kilocodeOrganizationId` to the cloud-agent worker?

### 3. Cloud Agent Worker - Session Prepare Handler

**File:** `cloud-agent/src/router/handlers/session-prepare.ts`

This handler receives the request from the backend and should:

1. Extract `input.kilocodeOrganizationId`
2. Pass it to `createKiloSessionInBackend()` as `organizationId`
3. Store it in the Durable Object via `stub.prepare({ orgId: input.kilocodeOrganizationId })`

**Questions to answer:**

- Is `input.kilocodeOrganizationId` being received correctly?
- Is it being stored in the Durable Object?

### 4. CLI Session Creation

**File:** `cloud-agent/src/session-service.ts` (line ~1133)

The `createKiloSessionInBackend()` method calls `cliSessions.createV2` with:

```typescript
const input = {
	created_on_platform: "cloud-agent",
	organization_id: organizationId ?? null,
	cloud_agent_session_id: cloudAgentSessionId,
	// ...
}
```

**Questions to answer:**

- Is `organizationId` being passed correctly to this method?
- Is the CLI session being created with the correct `organization_id`?

### 5. Balance Validation

**File:** `cloud-agent/src/balance-validation.ts`

The `validateAuthAndBalance()` function uses `orgId` to check balance:

```typescript
if (orgId) {
	headers.set("X-KiloCode-OrganizationId", orgId)
}
```

**Questions to answer:**

- Is the `orgId` being extracted correctly from the request?
- Is the balance check using the organization's balance or the user's personal balance?

### 6. Session Service - Environment Variables

**File:** `cloud-agent/src/session-service.ts` (line ~347)

When starting the CLI, the session service sets:

```typescript
if (kilocodeOrganizationId) {
	envVars.KILOCODE_ORGANIZATION_ID = kilocodeOrganizationId
}
```

**Questions to answer:**

- Is `kilocodeOrganizationId` available at this point?
- Is the CLI receiving the `KILOCODE_ORGANIZATION_ID` environment variable?

## Suggested Investigation Steps

1. **Add logging** to `src/app/api/cloud-agent/sessions/prepare/route.ts` to confirm:

    - `input.organizationId` is being received
    - `kilocodeOrganizationId` is being passed to `client.prepareSession()`

2. **Add logging** to `cloud-agent/src/router/handlers/session-prepare.ts` to confirm:

    - `input.kilocodeOrganizationId` is being received
    - It's being stored in the Durable Object

3. **Check the database** to see if the CLI session (`efd969c3-f424-4fad-85f8-700d33172047`) has the correct `organization_id` set.

4. **Check the Durable Object state** to see if `orgId` is stored correctly for the session.

## Expected Data Flow

```
Extension                    Backend Route                Cloud-Agent Worker           Durable Object
    |                             |                              |                          |
    |-- POST /prepare ----------->|                              |                          |
    |   organizationId: "9d27..." |                              |                          |
    |                             |-- prepareSession() --------->|                          |
    |                             |   kilocodeOrganizationId     |                          |
    |                             |                              |-- stub.prepare() ------->|
    |                             |                              |   orgId: "9d27..."       |
    |                             |                              |                          |
    |<-- kiloSessionId -----------|<-----------------------------|<-------------------------|
```

## Key Question

At which point in this flow is the `organizationId` being lost or not used for billing?
