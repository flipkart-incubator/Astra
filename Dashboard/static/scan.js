function recent_scans() {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
            resp = JSON.parse(this.responseText);
        
            for (key in resp)
            {
                if(location.href.search('reports.html') != -1)
                {

                    // scan_data = "<a href=/reports.html#"+resp[key]['scanid']+" onclick='location.reload()'>"+resp[key]['url']+"</a><br>";
                    scan_data = "<a href=/reports.html#"+resp[key]['scanid']+' target="_blank">'+resp[key]['url']+"</a><br>";
                    
                } 
                else
                {
                    
                    scan_data = "<a href=/reports.html#"+resp[key]['scanid']+">"+resp[key]['url']+"</a><br>";
                }

                // Update dictionary
                //console.log(resp[key]["scan_status"]);
                if(resp[key]["scan_status"] == "Completed")
                {
                  resp[key].scan_status = '<span class="label label-success">Completed</span>';
                }
                else
                {

                  resp[key].scan_status = '<span class="label label-warning">In Progress</span>';

                }
                resp[key].export_data = '<a href="/reports/'+resp[key]['scanid']+'"><u>Download</u></a>'
                resp[key].scanid = scan_data;
                resp[key].id = parseInt(key) + 1;
                //console.log(resp);
                
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
