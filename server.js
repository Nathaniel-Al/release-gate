const express = require('express');

const app = express();
app.use(express.json());

const SHA_RE = /^[0-9a-f]{40}$/;
const REQUIRED_PERMS = { contents: 'read', packages: 'write', 'id-token': 'none' };

function checkPolicy(body) {
  const violations = [];

  const target = body.target;
  const event = body.event;
  const ref = body.ref;
  const workflow = body.workflow || {};
  const image = body.image || {};
  const perms = workflow.permissions || {};
  const actions = Array.isArray(workflow.actions) ? workflow.actions : [];

  // 1. Exact least-privilege permissions, no extras, no substitutions.
  const permKeys = Object.keys(perms);
  const reqKeys = Object.keys(REQUIRED_PERMS);
  const noExtraKeys = permKeys.length === reqKeys.length &&
    permKeys.every((k) => reqKeys.includes(k));
  const valuesMatch = reqKeys.every((k) => perms[k] === REQUIRED_PERMS[k]);
  if (!noExtraKeys || !valuesMatch) {
    violations.push('EXCESS_PERMISSION');
  }

  // 2. PR trigger must never be pull_request_target when running as a PR.
  const isUnsafeTrigger =
    workflow.trigger === 'pull_request_target' ||
    (event === 'pull_request' && workflow.trigger !== 'pull_request');
  if (isUnsafeTrigger) {
    violations.push('UNSAFE_PR_TRIGGER');
  }

  // 3. Full matrix must run to completion with tests passing, no fail-fast.
  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.push('TESTS_INCOMPLETE');
  }

  // 4. Third-party actions must be pinned to a full 40-char lowercase SHA.
  //    Actions owned by "actions" may use a version tag instead.
  const hasMutableAction = actions.some((a) => {
    if (!a || a.owner === 'actions') return false;
    return !SHA_RE.test(String(a.ref || ''));
  });
  if (hasMutableAction) {
    violations.push('MUTABLE_ACTION');
  }

  // 5. Hardened image requirements.
  if (image.multiStage !== true) {
    violations.push('SINGLE_STAGE_IMAGE');
  }
  if (image.runsAsRoot !== false) {
    violations.push('ROOT_RUNTIME');
  }
  if (image.secretMode !== 'none' && image.secretMode !== 'buildkit') {
    violations.push('SECRET_IN_LAYER');
  }
  if (image.criticalVulnerabilities !== 0) {
    violations.push('CRITICAL_CVE');
  }
  if (image.digestPinned !== true) {
    violations.push('UNPINNED_IMAGE');
  }

  // 6. Production requires push-to-main and explicit environment approval.
  if (target === 'production') {
    if (!(event === 'push' && ref === 'refs/heads/main')) {
      violations.push('INVALID_PRODUCTION_REF');
    }
    if (workflow.environmentApproval !== true) {
      violations.push('APPROVAL_REQUIRED');
    }
  }

  return violations;
}

app.post('/release-gate', (req, res) => {
  const violations = checkPolicy(req.body || {});
  res.json({
    decision: violations.length === 0 ? 'promote' : 'block',
    violations,
  });
});

app.get('/', (_req, res) => {
  res.send('release-gate policy service is up');
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`release-gate listening on ${PORT}`));
}

module.exports = { app, checkPolicy };
