const semver = require('semver');
const { execSync } = require('child_process');

function getLatestGitHubVersion() {
  try {
    const tags = execSync('git tag -l "v*"').toString().split('\n').filter(Boolean);
    if (tags.length === 0) return '0.0.0';
    
    const versions = tags.map(tag => tag.replace('v', '')).filter(semver.valid);
    return versions.sort(semver.rcompare)[0];
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
    return versions.sort(semver.rcompare)[0];
  } catch (error) {
    // Package might not exist yet in npm
    return '0.0.0';
  }
}

function validateVersionBump(currentVersion, type) {
  const latestGitHub = getLatestGitHubVersion();
  const latestNpm = getLatestNpmVersion();
  const latest = semver.gt(latestGitHub, latestNpm) ? latestGitHub : latestNpm;
  
  if (semver.lte(currentVersion, latest)) {
    console.error(`Error: New version ${currentVersion} must be greater than latest version ${latest}`);
    process.exit(1);
  }

  const expectedVersion = semver.inc(latest, type);
  if (currentVersion !== expectedVersion) {
    console.error(`Error: Invalid version increment. Expected ${expectedVersion}, got ${currentVersion}`);
    process.exit(1);
  }
}

// Get the new version from npm version command output (removes 'v' prefix)
const newVersion = process.argv[2].replace('v', '');
const type = process.argv[3];

validateVersionBump(newVersion, type);
