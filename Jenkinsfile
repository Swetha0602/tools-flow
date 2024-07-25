pipeline {
    agent any
    environment {
        GITHUB_CREDS=credentials('swetha-github-creds')
        IMAGE_NAME= 'final-flow'
        IMAGE_REPO='sriswetha06/final-flow'
        IMAGE_VERSION='v2'
        DOCKERHUB_CREDS=credentials('swetha-docker-creds')
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
        stage('Build Docker Image') {
            steps {
                script {
                   sh 'sudo docker build -t $IMAGE_NAME . '
                }
            }
        }
           stage('Docker Login'){
            steps{
                withCredentials([usernamePassword(credentialsId: 'swetha-docker-creds', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
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
