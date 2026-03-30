---
description: >-
  This project demonstrates deploying a containerized Flask application on AWS
  EKS using Terraform, Docker, and Kubernetes, and exposing it to the internet
  via a LoadBalancer service.
---

# AWS-EKS-Deployment

#### Architecture Diagram

<figure><img src="../.gitbook/assets/lb_target_type_instance.png" alt=""><figcaption></figcaption></figure>

***

#### Request Flow

```
- ELB receives external traffic
- Service routes traffic to pods
- kube-proxy load balances requests
- Pods serve the Flask application
```

***

#### Tech Stack Used

* AWS (EKS, VPC, EC2, ECR, IAM, ELB)
* Kubernetes
* Docker
* Terraform
* Flask (python)

***

#### Features

* Containerized Flask application using docker multi-stage build
* Store Image in AWS ECR&#x20;
* Deployed on AWS EKS&#x20;
* Infrastructure provisioned via Terraform
* Exposed application externally using Kubernetes Service (type: LoadBalancer)

***

#### Steps to build

<details>

<summary>Clone GitHub repository</summary>

```bash
git clone https://github.com/pranavsoni21/aws-eks-deployment.git
cd aws-eks-deployment/
```

</details>

<details>

<summary>Build Docker Image</summary>

```bash
docker build -t flask-k8s-app app/.
```

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

```bash
docker tag \
flask-k8s-app:latest \
816709079541.dkr.ecr.ap-south-1.amazonaws.com/flask-k8s-app:latest
```

Get temporary login-password from AWS ECR to let docker push this image to our repo:

```bash
aws ecr get-login-password --region ap-south-1 | \
docker login \
--username AWS \
--password-stdin \
816709079541.dkr.ecr.ap-south-1.amazonaws.com/flask-k8s-app
```

Now, we are all set to push our docker image to AWS ECR:

```bash
docker push 816709079541.dkr.ecr.ap-south-1.amazonaws.com/flask-k8s-app:latest
```

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

For confirmation, we can also check this out on AWS console:

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Provision AWS Infrastructure via terraform</summary>

To provision whole infrastructure using terraform on AWS, you have to first configure your aws-cli with your AWS account who have permission to perform all this action.

Once you configured aws-cli, terraform will automatically use that configuration to provision infrastructure on-behalf of your AWS user.

```
cd terraform/
terraform init
terraform apply
```

<figure><img src="../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>

Make sure it will create all these 22 resources on AWS. It will take up to 10 minutes to create all these resources. Once it's done, we can move on to our next step.

</details>

<details>

<summary>Deploy app using Kubernetes</summary>

Before moving ahead, make sure you have kubectl installed on your machine.

```bash
pranav@Ubuntu:~/aws-eks-deployment/kubernetes$ kubectl version --client
Client Version: v1.35.3
Kustomize Version: v5.7.1
```

If not installed you can install with these following steps:\
[https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)

Once done, update kubeconfig file via aws-cli using these command:

```bash
aws eks update-kubeconfig --region ap-south-1 --name eks_cluster
```

It updates our local kubeConfig file with a new context named on our eks\_cluster, you can verify that and switch the context:

```bash
kubectl config get-contexts
```

<figure><img src="../.gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>

As we can see, our cluster context is added to config file and we are in that (\*) contexts. Now, we can verify this by checking nodes:&#x20;

```bash
pranav@Ubuntu:~/aws-eks-deployment/kubernetes$ kubectl get nodes
NAME                                        STATUS   ROLES    AGE     VERSION
ip-10-0-3-93.ap-south-1.compute.internal    Ready    <none>   5m21s   v1.30.14-eks-f69f56f
ip-10-0-4-167.ap-south-1.compute.internal   Ready    <none>   5m17s   v1.30.14-eks-f69f56f
```

Our nodes are all set and ready to go!

Before deploying our app on kubernetes, we need to create a secret (docker-registry), which it will need to pull image from our repository.

```bash
kubectl create secret docker-registry ecr-secret --docker-server=<ecr-uri> --docker-username=AWS --docker-password=$(aws ecr get-login-password --region ap-south-1)
```

Now, apply all the configuration files placed withing our Kubernetes directory

```bash
pranav@Ubuntu:~/aws-eks-deployment/kubernetes$ kubectl apply -f "*.yaml"
configmap/app-config created
deployment.apps/flask-deployment created
service/flask-service created
```

Wait for 2-3 minutes and then check service for elb url:

```bash
pranav@Ubuntu:~/aws-eks-deployment/kubernetes$ kubectl get svc
NAME            TYPE           CLUSTER-IP       EXTERNAL-IP                                                                PORT(S)        AGE
flask-service   LoadBalancer   172.20.191.140   a8632cbaf5a0b472ba7aafe3f73ce2ad-1248056373.ap-south-1.elb.amazonaws.com   80:32136/TCP   5s
kubernetes      ClusterIP      172.20.0.1       <none>                                                                     443/TCP        4m48s
```

Visit this URL, and you will be able to see that our app is successfully deployed to AWS EKS.

<figure><img src="../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Cleanup steps</summary>

First of all delete all the Kubernetes configurations:

```bash
kubectl delete -f "*.yaml"
```

Then, we can delete our ecr repository which we created manually:

```bash
aws ecr delete-repository --repository-name flask-k8s-app --force
```

Now, we can the delete whole infrastructure which we created using terrafrom:&#x20;

```bash
cd /terraform
terraform destroy --auto-approve
```

</details>

***

#### Common Questions

<details>

<summary>What problem does Kubernetes solve in this project?</summary>

```
Kubernetes solves the problem of managing containerized applications at scale.
In this project, it ensures that my Flask application runs reliably by handling
deployment, scaling, and self-healing.

For example, if a pod crashes, Kubernetes automatically recreates it. It also
maintains the desired number of replicas using ReplicaSets. Services provide
stable networking to access pods.

Overall, Kubernetes abstracts infrastructure complexity and ensures my
application is highly available, scalable, and production-ready.
```

</details>

<details>

<summary>Why did I use ECR instead of Docker Hub?</summary>

```
I used Amazon ECR instead of Docker Hub because it integrates natively with AWS services like EKS. 
This allows worker nodes to securely pull images using IAM roles without needing to manage external credentials.

It also improves performance and reliability since the images are stored within the same AWS region, reducing latency.

Additionally, using ECR keeps the architecture consistent within the AWS ecosystem, which simplifies management and enhances security compared to public registries like Docker Hub.
```

</details>

***

#### Key Learnings

* Understood how Kubernetes manages containerized applications
* Learned how AWS EKS integrates with EC2 and VPC networking
* Gained hands-on experience with Docker image lifecycle (build → push → deploy)
* Learned how Kubernetes Services expose applications externally using ELB
* Debugged real-world issues like ImagePullBackOff and IAM misconfigurations

***
