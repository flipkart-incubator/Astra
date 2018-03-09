function recent_scans() {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
            resp = JSON.parse(this.responseText);
            for (key in resp)
            {
                if(location.href.search('reports.html') != -1)
                {
                    document.getElementById("recentscans").innerHTML += "<a href=/reports.html#"+resp[key]['scanid']+" onclick='location.reload()'>"+resp[key]['name']+"</a><br>";
                }
                else
                {
                    document.getElementById("recentscans").innerHTML += "<a href=/reports.html#"+resp[key]['scanid']+">"+resp[key]['name']+"</a><br>";
                }
            }
    }
  };
  xhttp.open("GET", "/scan/scanids/", true);
  xhttp.send();
}
