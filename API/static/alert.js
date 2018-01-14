window.onload = loadDoc();
function loadDoc() {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
     results = JSON.parse(this.responseText);
     var vulname = document.getElementById("vulname");
     for (result in results){
	     
	     console.log(results[result]);
	     req_headers_data = results[result]['req_headers'];
	     res_headers_data = results[result]['res_headers'];

	     name = results[result]["name"];
	     url = results[result]["url"];
	     impact  = results[result]["impact"];
	     Description = results[result]["Description"];
	     Remediation = results[result]["remediation"];

 	     var alert_name = document.createElement("div");
 	     var btn=document.createElement("button");
 	     btn.type = 'button';
 	     btn.innerHTML = name +" in " + url;

 	     btn.setAttribute("id", "btn_id_"+result);
		 btn.setAttribute("class", "btn btn_info");
		 btn.setAttribute("width","100%");
		 // btn.classList.add("btn");
		 // btn.classList.add("btn_info");

		 // btn.setAttribute("style","color: red");

		 btn.setAttribute("data-toggle", "collapse"); 
		 btn.setAttribute("data-target", "#demo_"+result); 
		 
		 alert_name.appendChild(btn);

		 var collapse_div = document.createElement("div");
		 collapse_div.setAttribute('id',"demo_"+result);
		 collapse_div.setAttribute('class',"collapse");

		 var  req_header_div_data = "";
		 for (name in req_headers_data){
		 	req_header_div_data += "<b>"+name+"</b> : "+req_headers_data[name]+"</br>";
		 }
		 req_header_div_data += "</br>";
		 req_header_div_data += JSON.stringify(results[result]['req_body']);

		 var  res_header_div_data = "";
		 for (name in res_headers_data){
		 	res_header_div_data += "<b>"+name+"</b> : "+res_headers_data[name]+"</br>";
		 }

		var resp_body = results[result]['res_body'];
		if(resp_body != null)
		{
			 res_header_div_data += "</br>";
			 res_header_div_data += JSON.stringify(resp_body);
		}
		 collapse_div.innerHTML = '<table class="table"><tbody><tr><td style="width:50%">HTTP Request</td><td style="width:50%">HTTP Response</td></tr><tr><td style="background-color: black"><font color="white" id="font"><div id="http-req_"'+result+'>'+req_header_div_data+'</div></font></td><td style="background-color: black"><font color="white" id="font"><div id="http-req_"'+result+'>'+res_header_div_data+'</div></font></td></tr><tr><td style="background-color: black"><font color="white" id="font">Impact:</td><td style="background-color: black"><font color="white" id="font"><div id="impact_"'+result+'>'+impact+'</div></font></td><tr><td style="background-color: black"><font color="white" id="font">Description:</td><td style="background-color: black"><font color="white" id="font"><div id="Description"'+result+'>'+Description+'</div></font></td><tr><td style="background-color: black"><font color="white" id="font">Remediation</td><td style="background-color: black"><font color="white" id="font"><div id="Remediation"'+result+'>'+Remediation+'</div></font></td></table>';
		 alert_name.appendChild(collapse_div);
		 vulname.appendChild(alert_name);
     }
 
    }

  };
  xhttp.open("GET", "/alerts/", true);
  xhttp.send();

}