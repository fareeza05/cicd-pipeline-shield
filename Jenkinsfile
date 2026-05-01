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
                // Docker-out-of-Docker path translation: the host Docker daemon
                // needs macOS host paths, not the /var/jenkins_home path that
                // only exists inside the Jenkins container. We derive the host
                // path by inspecting the Jenkins container's own volume mounts
                // so no manual env-var configuration is required.
                sh '''
                    HOST_JH=$(docker inspect jenkins \
                        --format '{{range .Mounts}}{{if eq .Destination "/var/jenkins_home"}}{{.Source}}{{end}}{{end}}')
                    HOST_WS="${HOST_JH}/workspace/${JOB_NAME}"

                    mkdir -p "${WORKSPACE}/reports"
                    rm -f "${WORKSPACE}/reports/"*.json
                    docker run --rm \
                        --user $(id -u):$(id -g) \
                        -v "${HOST_WS}":/data:ro \
                        -v "${HOST_WS}/reports":/app/reports \
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
