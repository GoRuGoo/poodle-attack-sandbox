const reqDist = window.location.href;
let count = 0;
let id = null;
function reqListener() {
	console.log(this.responseText);
	console.log(count++)
}

function sendReq(){
	const req = new XMLHttpRequest();
	req.addEventListener("load", reqListener);
	req.open("GET", reqDist);
	req.send();
}

id = setInterval(sendReq, 1000);
