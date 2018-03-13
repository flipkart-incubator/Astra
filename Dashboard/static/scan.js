function recent_scans() {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
            resp = JSON.parse(this.responseText);
        
            for (key in resp)
            {
                if(location.href.search('reports.html') != -1)
                {

                    scan_data = "<a href=/reports.html#"+resp[key]['scanid']+" onclick='location.reload()'>"+resp[key]['url']+"</a><br>";
                    
                } 
                else
                {
                    
                    scan_data = "<a href=/reports.html#"+resp[key]['scanid']+">"+resp[key]['url']+"</a><br>";
                }

                // Update dictionary
                resp[key].scanid = scan_data;
                resp[key].id = parseInt(key) + 1;
                console.log(resp);
                
            }

             $(function () 
            {
                $('#table').bootstrapTable({
                data: resp
                 });
             });

    }
  };
  xhttp.open("GET", "/scan/scanids/", true);
  xhttp.send();
}
