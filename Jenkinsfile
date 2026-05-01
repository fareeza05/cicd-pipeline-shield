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
        IMAGE_NAME = 'shield-pipe'
        IMAGE_TAG  = "${env.BUILD_NUMBER}"
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
                    chmod 777 "${WORKSPACE}/reports"
                    rm -f reports/*.json
                    docker run --rm \
                        --user $(id -u):$(id -g) \
                        -v "${WORKSPACE}":/data:ro \
                        -v "${WORKSPACE}/reports":/app/reports \
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
