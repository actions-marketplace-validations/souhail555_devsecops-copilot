const params = new URLSearchParams(location.search);
document.getElementById("greeting").innerHTML = "Hello " + params.get("name");
fetch("/api/data", { headers: { "Access-Control-Allow-Origin": "*" } });
