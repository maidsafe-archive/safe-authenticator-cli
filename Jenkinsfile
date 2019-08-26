import hudson.triggers.TimerTrigger.TimerTriggerCause

properties([
    parameters([
        string(name: "ARTIFACTS_BUCKET", defaultValue: "safe-jenkins-build-artifacts"),
        string(name: "CACHE_BRANCH", defaultValue: "master"),
        string(name: "DEPLOY_BUCKET", defaultValue: "safe-authenticator-cli"),
        string(name: "DEPLOY_NIGHTLY", defaultValue: "false")
    ]),
    pipelineTriggers([cron(env.BRANCH_NAME == "master" ? "@midnight" : "")])
])

stage("build & test") {
    parallel test_linux: {
        node("safe_auth") {
            checkout(scm)
            sh("make test")
            packageBuildArtifacts("linux", "dev")
            uploadBuildArtifacts()
        }
    },
    test_windows: {
        node("windows") {
            checkout(scm)
            retrieveCache()
            sh("make test")
            packageBuildArtifacts("windows", "dev")
            uploadBuildArtifacts()
        }
    },
    test_macos: {
        node("osx") {
            checkout(scm)
            sh("make test")
            packageBuildArtifacts("macos", "dev")
            uploadBuildArtifacts()
        }
    },
    release_linux: {
        node("safe_auth") {
            checkout(scm)
            sh("make build")
            packageBuildArtifacts("linux", "release")
            uploadBuildArtifacts()
        }
    },
    release_windows: {
        node("windows") {
            checkout(scm)
            sh("make build")
            packageBuildArtifacts("windows", "release")
            uploadBuildArtifacts()
        }
    },
    release_macos: {
        node("osx") {
            checkout(scm)
            sh("make build")
            packageBuildArtifacts("macos", "release")
            uploadBuildArtifacts()
        }
    }
}

stage("deploy") {
    node("safe_auth") {
        if (env.BRANCH_NAME == "PR-65") {
            checkout(scm)
            sh("git fetch --tags --force")
            retrieveBuildArtifacts()
            if (isNightlyBuild()) {
                packageArtifactsForDeploy("nightly")
                uploadDeployArtifacts("nightly")
            } else if (isVersionChangeCommit()) {
                version = sh(
                    returnStdout: true,
                    script: "grep '^version' < Cargo.toml | head -n 1 | awk '{ print \$3 }' | sed 's/\"//g'").trim()
                packageArtifactsForDeploy("versioned")
                createTag(version)
                createGithubRelease(version)
                uploadDeployArtifacts("dev")
            } else {
                packageArtifactsForDeploy("commit_hash")
                uploadDeployArtifacts("dev")
                uploadDeployArtifacts("release")
            }
        } else {
            echo("${env.BRANCH_NAME} does not match the deployment branch. Nothing to do.")
        }
    }
    if (env.BRANCH_NAME == "master") {
        build(job: "../rust_cache_build-safe_auth_cli-windows", wait: false)
        build(job: "../docker_build-safe_auth_cli_build_container", wait: false)
    }
}

def retrieveCache() {
    if (!fileExists("target")) {
        withEnv(["SAFE_AUTH_BRANCH=${params.CACHE_BRANCH}"]) {
            sh("make retrieve-cache")
        }
    }
}

def packageBuildArtifacts(os, type) {
    branch = env.CHANGE_ID?.trim() ?: env.BRANCH_NAME
    withEnv(["SAFE_AUTH_BRANCH=${branch}",
             "SAFE_AUTH_BUILD_NUMBER=${env.BUILD_NUMBER}",
             "SAFE_AUTH_BUILD_TYPE=${type}",
             "SAFE_AUTH_BUILD_OS=${os}"]) {
        sh("make package-build-artifacts")
    }
}

def uploadBuildArtifacts() {
    withAWS(credentials: "aws_jenkins_build_artifacts_user", region: "eu-west-2") {
        def artifacts = sh(returnStdout: true, script: "ls -1 artifacts").trim().split("\\r?\\n")
        for (artifact in artifacts) {
            s3Upload(
                bucket: "${params.ARTIFACTS_BUCKET}",
                file: artifact,
                workingDir: "${env.WORKSPACE}/artifacts",
                acl: "PublicRead")
        }
    }
}

def retrieveBuildArtifacts() {
    branch = env.CHANGE_ID?.trim() ?: env.BRANCH_NAME
    withEnv(["SAFE_AUTH_BRANCH=${branch}",
             "SAFE_AUTH_BUILD_NUMBER=${env.BUILD_NUMBER}"]) {
        sh("make retrieve-all-build-artifacts")
    }
}

@NonCPS
def isNightlyBuild() {
    return "${params.DEPLOY_NIGHTLY}" == "true" ||
        null != currentBuild.getRawBuild().getCause(TimerTriggerCause.class)
}

def isVersionChangeCommit() {
    shortCommitHash = sh(
        returnStdout: true,
        script: "git log -n 1 --no-merges --pretty=format:'%h'").trim()
    message = sh(
        returnStdout: true,
        script: "git log --format=%B -n 1 ${shortCommitHash}").trim()
    return message.startsWith("Version change")
}

def packageArtifactsForDeploy(type) {
    switch (type) {
        case "nightly":
            sh("make package-nightly-artifacts-for-deploy")
            break
        case "versioned":
            sh("make package-version-artifacts-for-deploy")
            break
        case "commit_hash":
            sh("make package-commit_hash-artifacts-for-deploy")
            break
        default:
            error("This deployment type is not supported. Please extend for support.")
    }
}

def uploadDeployArtifacts(type) {
    withAWS(credentials: "aws_jenkins_deploy_artifacts_user", region: "eu-west-2") {
        if (type == "nightly") {
            s3Delete(
                bucket: "${params.DEPLOY_BUCKET}",
                path: "safe_authenticator_cli-nightly-x86_64-unknown-linux-gnu.tar")
            s3Delete(
                bucket: "${params.DEPLOY_BUCKET}",
                path: "safe_authenticator_cli-nightly-x86_64-pc-windows-gnu.tar")
            s3Delete(
                bucket: "${params.DEPLOY_BUCKET}",
                path: "safe_authenticator_cli-nightly-x86_64-apple-darwin.tar")
        }
        subDirectory = type == "nightly" ? "dev" : type
        def artifacts = sh(
            returnStdout: true, script: "ls -1 deploy/${subDirectory}").trim().split(
                "\\r?\\n")
        for (artifact in artifacts) {
            s3Upload(
                bucket: "${params.DEPLOY_BUCKET}",
                file: artifact,
                workingDir: "${env.WORKSPACE}/deploy/${subDirectory}",
                acl: "PublicRead")
        }
    }
}

def createTag(version) {
    withCredentials(
        [usernamePassword(
            credentialsId: "github_maidsafe_qa_user_credentials",
            usernameVariable: "GIT_USER",
            passwordVariable: "GIT_PASSWORD")]) {
        sh("git config --global user.name \$GIT_USER")
        sh("git config --global user.email qa@maidsafe.net")
        sh("git config credential.username \$GIT_USER")
        sh("git config credential.helper '!f() { echo password=\$GIT_PASSWORD; }; f'")
        sh("git tag -a ${version} -m 'Creating tag for ${version}'")
        sh("GIT_ASKPASS=true git push origin --tags")
    }
}

def createGithubRelease(version) {
    withCredentials(
        [usernamePassword(
            credentialsId: "github_maidsafe_token_credentials",
            usernameVariable: "GITHUB_USER",
            passwordVariable: "GITHUB_TOKEN")]) {
        sh("make deploy-github-release")
    }
}
