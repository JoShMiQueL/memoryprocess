import { valid, rcompare, gt, lte, inc } from 'semver';
import { execSync } from 'child_process';

function getLatestGitHubVersion() {
  try {
    const tags = execSync('git tag -l "v*"').toString().split('\n').filter(Boolean);
    if (tags.length === 0) return '0.0.0';
    
    const versions = tags.map(tag => tag.replace('v', '')).filter(valid);
    return versions.sort(rcompare)[0];
  } catch (error) {
    console.error('Error getting GitHub tags:', error);
    process.exit(1);
  }
}

function getLatestNpmVersion() {
  try {
    const npmInfo = execSync('npm view @joshmiquel/memoryjs versions --json').toString();
    const versions = JSON.parse(npmInfo);
    if (!versions || versions.length === 0) return '0.0.0';
    return versions.sort(rcompare)[0];
  } catch (error) {
    // Package might not exist yet in npm
    return '0.0.0';
  }
}

function validateVersionBump(currentVersion, type) {
  const latestGitHub = getLatestGitHubVersion();
  const latestNpm = getLatestNpmVersion();

  // If version exists in GitHub but not in npm, allow re-releasing the same version
  if (currentVersion === latestGitHub && gt(latestGitHub, latestNpm)) {
    console.log(`Re-releasing version ${currentVersion} to npm...`);
    return;
  }

  // For new versions, ensure they're greater than both GitHub and npm versions
  const latest = gt(latestGitHub, latestNpm) ? latestGitHub : latestNpm;
  if (lte(currentVersion, latest)) {
    console.error(`Error: New version ${currentVersion} must be greater than latest version ${latest}`);
    process.exit(1);
  }

  const expectedVersion = inc(latest, type);
  if (currentVersion !== expectedVersion) {
    console.error(`Error: Invalid version increment. Expected ${expectedVersion}, got ${currentVersion}`);
    process.exit(1);
  }
}

// Get the new version from npm version command output
const rawVersion = process.argv[2];
const type = process.argv[3];

// Extract only the version number, handling both 'v1.0.0' and npm version output
const versionMatch = rawVersion.match(/v?(\d+\.\d+\.\d+)/i);
if (!versionMatch) {
  console.error('Error: Invalid version format');
  process.exit(1);
}

validateVersionBump(versionMatch[1], type);
