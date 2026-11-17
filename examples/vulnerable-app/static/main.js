const params = new URLSearchParams(location.search);
document.getElementById("greeting").textContent = "Hello " + params.get("name");
fetch("/api/data");
