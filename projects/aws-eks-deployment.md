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

{% stepper %}
{% step %}
### Clone github repository

```
git clone https://github.com/pranavsoni21/aws-eks-deployment.git
```
{% endstep %}

{% step %}
### Build docker image

```
docker build -t flask-k8s-app app/.
```

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

After this, you will end up with a docker image(flask-k8s-app:latest) locally:

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

As I built multi-staged Dockerfile, you can see the actual image size is very less (around 40 MB).&#x20;
{% endstep %}

{% step %}
### Push Image to ECR Repository


{% endstep %}
{% endstepper %}







