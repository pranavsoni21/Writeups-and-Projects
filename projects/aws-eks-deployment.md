---
description: Deploying Flask App on AWS EKS with Terraform, Docker, and Kubernetes
---

# AWS-EKS-Deployment

#### Architecture Diagram:



***

#### Tech Stack Used:

* AWS (EKS, VPC, ECR, EC2, IAM, ALB)
* Kubernetes
* Docker
* Terraform
* Flask (python)

***

#### Features:

* Containerized Flask application using docker multi-stage build
* Store Image in AWS ECR&#x20;
* Deployed on AWS EKS&#x20;
* Infrastructure provisioned via Terraform
* Exposed via ALB Ingress

***

#### Steps to build:

<details>

<summary>Clone GitHub repository</summary>

```bash
git clone https://github.com/pranavsoni21/aws-eks-deployment.git
cd /aws-eks-deployment
```

</details>

<details>

<summary>Build Docker Image</summary>

{% code fullWidth="true" %}
```bash
docker build -t flask-k8s-app app/.
```
{% endcode %}

<figure><img src="../.gitbook/assets/Screenshot 2026-03-21 173401.png" alt=""><figcaption></figcaption></figure>

After this, you will end up with a docker image (flask-k8s-app:latest) built locally:

<figure><img src="../.gitbook/assets/Screenshot 2026-03-21 173612.png" alt=""><figcaption></figcaption></figure>

As I built multi-staged Dockerfile, you can see the image is very less - around 40 MB.

</details>

<details>

<summary><strong>Push Image to Docker Registry ( I used AWS ECR )</strong></summary>

To perform this step, first you have to create a ECR repository on AWS:

Before creating AWS ECR repository via cli, make sure you already configured aws-cli with valid credentials and with needed IAM permission.

```bash
aws ecr create-repository --repository-name flask-k8s-app --image-scanning-configuration scanOnPush=true --region ap-south-1
```

After repository creation, output will print out your repository URI like these, copy it somewhere as we will use it very often:

```
"repositoryUri": "<account-id>.dkr.ecr.ap-south-1.amazonaws.com/flask-k8s-app"
```

Now, tag your image for pushing it to ECR:

```
```





</details>



