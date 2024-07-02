pipeline {
    agent any
    environment {
        GITHUB_CREDS=credentials('Github_creds')
        IMAGE_NAME= 'final-flow'
        IMAGE_REPO='sriswetha06/final-flow'
        IMAGE_VERSION='v2'
        DOCKERHUB_CREDS=credentials('dockerhub-creds')
        COSIGN_PASSWORD=credentials('cosign-password')
        COSIGN_PRIVATE_KEY=credentials('cosign-private-key')
        COSIGN_PUBLIC_KEY=credentials('cosign-public-key')
    }
     stages {
          stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/Swetha0602/flask-app.git'
                sh 'git pull origin main'
            }
          }
         stage('Pre SAST') {
             steps {
                 sh 'gitleaks version'
                 sh 'gitleaks detect --source . -v || true'
             }
         }
          stage('Bandit Scan') {
            steps {
                script {
                   sh 'echo "yes" | sudo apt install python3-bandit'
                   sh 'bandit --version'
                   sh  'bandit -r . || true'
                }
            }
          }
         stage('Fossid Scan') {
               steps {
                   script {
                       sh ''' python3 workbench-agent.py \
                	    --api_url http://tefossid.tataelxsi.co.in/api.php\
                        --api_user 37786 \
                        --api_token EJWIALQVINDe7D07IFZxC6Ee1uwoFh67biGNGXdPvm \
                        --project_code ${JOB_NAME} \
                        --scan_code jenkins_fossid:${BUILD_NUMBER} \
                        --path ${WORKSPACE} \
                        --limit 1 \
                        --auto_identification_detect_declaration \
                        --auto_identification_detect_copyright \
                        --auto_identification_resolve_pending_ids \
                        --delta_only \
                        --log DEBUG \
                        --projects_get_policy_warnings_info \
                        --path-result fossid/ 
                        '''
                   }
               }
         }
        stage('Build Docker Image') {
            steps {
                script {
                   sh 'sudo docker build -t $IMAGE_NAME . '
                }
            }
        }
           stage('Docker Login'){
            steps{
                withCredentials([usernamePassword(credentialsId: 'dockerhub-creds', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
                      sh "docker login -u $USERNAME -p $PASSWORD"
                }
            }
        }
        stage ('Tag and Push') {
            steps {
                script {
                    sh 'sudo docker tag $IMAGE_NAME $IMAGE_REPO:$IMAGE_VERSION'
                    sh 'sudo docker push $IMAGE_REPO:$IMAGE_VERSION'
                }
            }
        }
        stage('Trivy Scan') {
            steps {
                sh 'trivy image $IMAGE_REPO:$IMAGE_VERSION'
            }
        }
        stage('Sign and Verify image with Cosign'){
            steps{
                sh 'echo "y" | cosign sign --key $COSIGN_PRIVATE_KEY docker.io/$IMAGE_REPO:$IMAGE_VERSION'
                sh 'cosign verify --key $COSIGN_PUBLIC_KEY docker.io/$IMAGE_REPO:$IMAGE_VERSION'
                echo 'Image signed successfully'
            }
        }
    }
}
