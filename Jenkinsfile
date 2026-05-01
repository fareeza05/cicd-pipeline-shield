// Shield-Pipe CI/CD pipeline.
// Build the scanner image, run it against the workspace, and fail
// the build if the scanner exits non-zero (security gate).
//
// Assumes Jenkins runs in a container with the host Docker socket
// mounted (Docker-out-of-Docker) so `docker` commands here reach
// the host daemon. See README "Jenkins setup" for details.

pipeline {
    agent any

    environment {
        IMAGE_NAME     = 'shield-pipe'
        IMAGE_TAG      = "${env.BUILD_NUMBER}"
        // HOST_JENKINS_HOME must be set as a Jenkins global env var
        // (Manage Jenkins → Configure System → Global properties) to the
        // macOS path that was bind-mounted as /var/jenkins_home in the
        // Jenkins container.  Without it the docker daemon receives an
        // in-container path (/var/jenkins_home/…) that doesn't exist on the
        // macOS host, so Docker Desktop creates it as root and the scanner
        // (UID 1000) gets Permission denied writing the report.
        HOST_WORKSPACE = "${env.HOST_JENKINS_HOME}/workspace/${env.JOB_NAME}"
    }

    options {
        timestamps()
        timeout(time: 10, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build') {
            steps {
                sh 'docker build -t ${IMAGE_NAME}:${IMAGE_TAG} -f deployment/Dockerfile .'
            }
        }

        stage('Scan') {
            steps {
                // Source mounted read-only (defense in depth: untrusted code
                // shouldn't be able to mutate the workspace from inside the
                // container). Reports mounted read-write so the JSON lands
                // back on the host for archival.
                sh '''
                    mkdir -p "${WORKSPACE}/reports"
                    rm -f "${WORKSPACE}/reports/"*.json
                    docker run --rm \
                        --user $(id -u):$(id -g) \
                        -v "${HOST_WORKSPACE}":/data:ro \
                        -v "${HOST_WORKSPACE}/reports":/app/reports \
                        ${IMAGE_NAME}:${IMAGE_TAG} /data
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/*.json',
                             allowEmptyArchive: true,
                             fingerprint: true
        }
        success {
            echo 'Shield-Pipe: SCAN PASSED — no security risks found.'
        }
        failure {
            echo 'Shield-Pipe: SCAN FAILED — see archived security_report.json.'
        }
        cleanup {
            // Best-effort image removal so old build tags don't pile up
            // on the Jenkins host. Failure here must not fail the build.
            sh 'docker rmi ${IMAGE_NAME}:${IMAGE_TAG} || true'
        }
    }
}
