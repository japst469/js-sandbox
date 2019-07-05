'use strict';  

const convert = { bin2dec : s => parseInt(s, 2).toString(10), bin2hex : s => parseInt(s, 2).toString(16), dec2bin : s => parseInt(s, 10).toString(2), dec2hex : s => parseInt(s, 10).toString(16), hex2bin : s => parseInt(s, 16).toString(2), hex2dec : s => parseInt(s, 16).toString(10) };

/* * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message * Digest Algorithm, as defined in RFC 1321. * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet * Distributed under the BSD License * See http://pajhome.org.uk/crypt/md5 for more info. */ var hexcase=0;function hex_md5(a){return rstr2hex(rstr_md5(str2rstr_utf8(a)))}function hex_hmac_md5(a,b){return rstr2hex(rstr_hmac_md5(str2rstr_utf8(a),str2rstr_utf8(b)))}function md5_vm_test(){return hex_md5("abc").toLowerCase()=="900150983cd24fb0d6963f7d28e17f72"}function rstr_md5(a){return binl2rstr(binl_md5(rstr2binl(a),a.length*8))}function rstr_hmac_md5(c,f){var e=rstr2binl(c);if(e.length>16){e=binl_md5(e,c.length*8)}var a=Array(16),d=Array(16);for(var b=0;b<16;b++){a[b]=e[b]^909522486;d[b]=e[b]^1549556828}var g=binl_md5(a.concat(rstr2binl(f)),512+f.length*8);return binl2rstr(binl_md5(d.concat(g),512+128))}function rstr2hex(c){try{hexcase}catch(g){hexcase=0}var f=hexcase?"0123456789ABCDEF":"0123456789abcdef";var b="";var a;for(var d=0;d<c.length;d++){a=c.charCodeAt(d);b+=f.charAt((a>>>4)&15)+f.charAt(a&15)}return b}function str2rstr_utf8(c){var b="";var d=-1;var a,e;while(++d<c.length){a=c.charCodeAt(d);e=d+1<c.length?c.charCodeAt(d+1):0;if(55296<=a&&a<=56319&&56320<=e&&e<=57343){a=65536+((a&1023)<<10)+(e&1023);d++}if(a<=127){b+=String.fromCharCode(a)}else{if(a<=2047){b+=String.fromCharCode(192|((a>>>6)&31),128|(a&63))}else{if(a<=65535){b+=String.fromCharCode(224|((a>>>12)&15),128|((a>>>6)&63),128|(a&63))}else{if(a<=2097151){b+=String.fromCharCode(240|((a>>>18)&7),128|((a>>>12)&63),128|((a>>>6)&63),128|(a&63))}}}}}return b}function rstr2binl(b){var a=Array(b.length>>2);for(var c=0;c<a.length;c++){a[c]=0}for(var c=0;c<b.length*8;c+=8){a[c>>5]|=(b.charCodeAt(c/8)&255)<<(c%32)}return a}function binl2rstr(b){var a="";for(var c=0;c<b.length*32;c+=8){a+=String.fromCharCode((b[c>>5]>>>(c%32))&255)}return a}function binl_md5(p,k){p[k>>5]|=128<<((k)%32);p[(((k+64)>>>9)<<4)+14]=k;var o=1732584193;var n=-271733879;var m=-1732584194;var l=271733878;for(var g=0;g<p.length;g+=16){var j=o;var h=n;var f=m;var e=l;o=md5_ff(o,n,m,l,p[g+0],7,-680876936);l=md5_ff(l,o,n,m,p[g+1],12,-389564586);m=md5_ff(m,l,o,n,p[g+2],17,606105819);n=md5_ff(n,m,l,o,p[g+3],22,-1044525330);o=md5_ff(o,n,m,l,p[g+4],7,-176418897);l=md5_ff(l,o,n,m,p[g+5],12,1200080426);m=md5_ff(m,l,o,n,p[g+6],17,-1473231341);n=md5_ff(n,m,l,o,p[g+7],22,-45705983);o=md5_ff(o,n,m,l,p[g+8],7,1770035416);l=md5_ff(l,o,n,m,p[g+9],12,-1958414417);m=md5_ff(m,l,o,n,p[g+10],17,-42063);n=md5_ff(n,m,l,o,p[g+11],22,-1990404162);o=md5_ff(o,n,m,l,p[g+12],7,1804603682);l=md5_ff(l,o,n,m,p[g+13],12,-40341101);m=md5_ff(m,l,o,n,p[g+14],17,-1502002290);n=md5_ff(n,m,l,o,p[g+15],22,1236535329);o=md5_gg(o,n,m,l,p[g+1],5,-165796510);l=md5_gg(l,o,n,m,p[g+6],9,-1069501632);m=md5_gg(m,l,o,n,p[g+11],14,643717713);n=md5_gg(n,m,l,o,p[g+0],20,-373897302);o=md5_gg(o,n,m,l,p[g+5],5,-701558691);l=md5_gg(l,o,n,m,p[g+10],9,38016083);m=md5_gg(m,l,o,n,p[g+15],14,-660478335);n=md5_gg(n,m,l,o,p[g+4],20,-405537848);o=md5_gg(o,n,m,l,p[g+9],5,568446438);l=md5_gg(l,o,n,m,p[g+14],9,-1019803690);m=md5_gg(m,l,o,n,p[g+3],14,-187363961);n=md5_gg(n,m,l,o,p[g+8],20,1163531501);o=md5_gg(o,n,m,l,p[g+13],5,-1444681467);l=md5_gg(l,o,n,m,p[g+2],9,-51403784);m=md5_gg(m,l,o,n,p[g+7],14,1735328473);n=md5_gg(n,m,l,o,p[g+12],20,-1926607734);o=md5_hh(o,n,m,l,p[g+5],4,-378558);l=md5_hh(l,o,n,m,p[g+8],11,-2022574463);m=md5_hh(m,l,o,n,p[g+11],16,1839030562);n=md5_hh(n,m,l,o,p[g+14],23,-35309556);o=md5_hh(o,n,m,l,p[g+1],4,-1530992060);l=md5_hh(l,o,n,m,p[g+4],11,1272893353);m=md5_hh(m,l,o,n,p[g+7],16,-155497632);n=md5_hh(n,m,l,o,p[g+10],23,-1094730640);o=md5_hh(o,n,m,l,p[g+13],4,681279174);l=md5_hh(l,o,n,m,p[g+0],11,-358537222);m=md5_hh(m,l,o,n,p[g+3],16,-722521979);n=md5_hh(n,m,l,o,p[g+6],23,76029189);o=md5_hh(o,n,m,l,p[g+9],4,-640364487);l=md5_hh(l,o,n,m,p[g+12],11,-421815835);m=md5_hh(m,l,o,n,p[g+15],16,530742520);n=md5_hh(n,m,l,o,p[g+2],23,-995338651);o=md5_ii(o,n,m,l,p[g+0],6,-198630844);l=md5_ii(l,o,n,m,p[g+7],10,1126891415);m=md5_ii(m,l,o,n,p[g+14],15,-1416354905);n=md5_ii(n,m,l,o,p[g+5],21,-57434055);o=md5_ii(o,n,m,l,p[g+12],6,1700485571);l=md5_ii(l,o,n,m,p[g+3],10,-1894986606);m=md5_ii(m,l,o,n,p[g+10],15,-1051523);n=md5_ii(n,m,l,o,p[g+1],21,-2054922799);o=md5_ii(o,n,m,l,p[g+8],6,1873313359);l=md5_ii(l,o,n,m,p[g+15],10,-30611744);m=md5_ii(m,l,o,n,p[g+6],15,-1560198380);n=md5_ii(n,m,l,o,p[g+13],21,1309151649);o=md5_ii(o,n,m,l,p[g+4],6,-145523070);l=md5_ii(l,o,n,m,p[g+11],10,-1120210379);m=md5_ii(m,l,o,n,p[g+2],15,718787259);n=md5_ii(n,m,l,o,p[g+9],21,-343485551);o=safe_add(o,j);n=safe_add(n,h);m=safe_add(m,f);l=safe_add(l,e)}return Array(o,n,m,l)}function md5_cmn(h,e,d,c,g,f){return safe_add(bit_rol(safe_add(safe_add(e,h),safe_add(c,f)),g),d)}function md5_ff(g,f,k,j,e,i,h){return md5_cmn((f&k)|((~f)&j),g,f,e,i,h)}function md5_gg(g,f,k,j,e,i,h){return md5_cmn((f&j)|(k&(~j)),g,f,e,i,h)}function md5_hh(g,f,k,j,e,i,h){return md5_cmn(f^k^j,g,f,e,i,h)}function md5_ii(g,f,k,j,e,i,h){return md5_cmn(k^(f|(~j)),g,f,e,i,h)}function safe_add(a,d){var c=(a&65535)+(d&65535);var b=(a>>16)+(d>>16)+(c>>16);return(b<<16)|(c&65535)}function bit_rol(a,b){return(a<<b)|(a>>>(32-b))}; 

function getMedian(a){ var s = a.sort((a,b) => {return a-b;}); i = Math.floor((s.length-1)/2); return s[i]+(s[i+1]-s[i])/2; };

function arrayMerge( arr1, arr2 ){
  function arrayUnique(arr) {
    var a = arr.concat();
    for(var i=0; i<a.length; ++i) {
        for(var j=i+1; j<a.length; ++j) {
            if(a[i] === a[j])
                a.splice(j--, 1);
        }
    }

    return a;
  }

  var result = arrayUnique(arr1.concat(arr2));
  //var txt = "";
  //result.forEach( (e,i,a)=>{ txt+=(e + "\n"); } );
  return result;
}
function arrayRemove( array, element ) {
	if( Object.prototype.toString.call(array) === '[object Array]' ) {
		let index = array.indexOf( element );
		if( index !== -1 ) {
			array.splice( index, 1 );
			return array;
		} else {
			// no such element
			return array;
		}
	}
}
/*/
const ascii = ['','','','','','','','','','\t','^J','','','^M','','','','','','','','','','','','','','','','','','',' ','!','"','#','$','%','&','\'','(',')','*','+',',','-','.','/','0','1','2','3','4','5','6','7','8','9',':',';','<','=','>','?','@','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','[','\\',']','^','_','`','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','{','|','}','~','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','','',' ','¡','¢','£','¤','¥','¦','§','¨','©','ª','«','¬','­','®','¯','°','±','²','³','´','µ','¶','·','¸','¹','º','»','¼','½','¾','¿','À','Á','Â','Ã','Ä','Å','Æ','Ç','È','É','Ê','Ë','Ì','Í','Î','Ï','Ð','Ñ','Ò','Ó','Ô','Õ','Ö','×','Ø','Ù','Ú','Û','Ü','Ý','Þ','ß','à','á','â','ã','ä','å','æ','ç','è','é','ê','ë','ì','í','î','ï','ð','ñ','ò','ó','ô','õ','ö','÷','ø','ù','ú','û','ü','ý','þ','ÿ'];
/*/
const alphabet = ['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'];


// Artoo bookmarklet
javascript: (function(){var t={},e=!0;if("object"==typeof this.artoo&&(artoo.settings.reload||(artoo.log.verbose("artoo already exists within this page. No need to inject him again."),artoo.loadSettings(t),artoo.exec(),e=!1)),e){var o=document.getElementsByTagName("body")[0];o||(o=document.createElement("body"),document.documentElement.appendChild(o));var a=document.createElement("script");console.log("artoo.js is loading..."),a.src="//medialab.github.io/artoo/public/dist/artoo-latest.min.js",a.type="text/javascript",a.id="artoo_injected_script",a.setAttribute("settings",JSON.stringify(t)),o.appendChild(a)}}).call(this);


artoo.ajaxSniffer.after((req,res) => { if( res.data.auctionsDetails !== "undefined" ){ if( history[0][2] === history[2][2] === history[4][2] ){ alert("Check it"); } } } );

//regex page search requires jQuery
javascript:void((function(){ var sheet = (function() {var style = document.createElement("style");style.appendChild(document.createTextNode(""));document.head.appendChild(style);return style.sheet;})(); sheet.insertRule(".regexhighlightedtext { background-color: yellow;}",0);if($('.regexhighlightedtext')!==null){$('.regexhighlightedtext').removeClass('regexhighlightedtext')}; b=document.body;var rg = new RegExp("(>{1}[^\n\<]*?)("+prompt("Please enter the regular expression to search for.")+")", "g"); b.innerHTML=b.innerHTML.replace(rg,'$1<span class="regexhighlightedtext">$2</span>');})())

function google_data() {
	var google_results = artoo.scrape('div.srg h3.r a', 
	{ g_url: function() { return $(this).attr('href'); },
	 d_url: function() { return $(this).attr('data-href'); }, 
	 title: function() { return $(this).text(); },
	 keyphrase: function() { return window.location.href.match(/q=[^&]*/g)[0].replace("/\+/g"," ").replace("q=","").replace("%3A","-"); },
	 DA: function(){ return parseInt($(this).context.parentNode.parentNode.lastChild.contentDocument.lastChild.innerText.match(/DA: \d.*\n/g)[0].replace("DA: ","").trim());}, 
	 pos: function(){ return parseInt(window.location.href.match(/start=(\d*)&/g)!==null?window.location.href.match(/start=(\d*)&/g)[0].match(/\d+/gi):0) + parseInt($(this).context.parentNode.parentNode.lastChild.contentDocument.lastChild.innerText.match(/\d\)\n/g)[0].replace(/\)\n/g,"").trim());} 
	} ).sort( (a,b) => { return a.DA-b.DA; } );
   artoo.savePrettyJson( google_results, new Date().toLocaleString() + "-"+window.location.href.match(/q=[^&]*/g)[0].replace("/\+/g"," ").replace("q=","").replace("%3A","-")+".json" );
   // reduce the array to the first five results.
   google_results.splice(5,google_results.length-5); 
   // perform a post to the seo_ninjas site comparison tool. formdata: "urls=" + urls + "&submit=Ninja+Check"
   var urls = ""; google_results.forEach( (i)=>{ urls += encodeURI( i.g_url ); } );
   // Im going to have to navigate to the ninja site to perform a crawl... otherwise there is CORS problems.
   Window.location( 'https://www.internetmarketingninjas.com/seo-tools/seo-compare/' );
   urls = 'urls=' + urls + '&submit=Ninja+Check';
   artoo.ajaxSpider( ['https://www.internetmarketingninjas.com/seo-tools/seo-compare/'], {
	   method: 'post',
	   data: urls,
	   scrape: {
			summary: artoo.scrapeTable('#sc-summary', { headers: 'th'}),
			title: artoo.scrapeTable('#sc-title', { headers: 'th'}),
			desc: artoo.scrapeTable('#sc-description', { headers: 'th' } ),
			keywords: artoo.scrapeTable('#sc-keywords', { headers: 'th' } ),
			headings: artoo.scrapeTable('#sc-headings', { headers: 'th' } ),
			//twophrase: { heads: artoo.scrapeTable('#sc-phrases2', { headers: 'th' } ), phrases: artoo.scrapeTable('#sc-phrases2.sc-phraseList', { headers: 'th' } ) },
			text: artoo.scrapeTable('#sc-alltext', { headers: 'th' , done: function(d){ d.forEach((i)=>{i.chars = i['Text On-page'].length; i.words = i['Text On-page'].split(' ').length; }) } } )
		},
		function(data){
			return alert( data );
		}
   });
};	
javascript: (function(){var t={eval:google_data()},e=!0;if("object"==typeof this.artoo&&(artoo.settings.reload||(artoo.log.verbose("artoo already exists within this page. No need to inject him again."),artoo.loadSettings(t),artoo.exec(),e=!1)),e){var o=document.getElementsByTagName("body")[0];o||(o=document.createElement("body"),document.documentElement.appendChild(o));var a=document.createElement("script");console.log("artoo.js is loading..."),a.src="//medialab.github.io/artoo/public/dist/artoo-latest.min.js",a.type="text/javascript",a.id="artoo_injected_script",a.setAttribute("settings",JSON.stringify(t)),o.appendChild(a)}}).call(this);


function fn() {
	var plugins = { title: artoo.scrapeTable('.plugins', { headers: 'th'}) };
   artoo.savePrettyJson( plugins, new Date().toLocaleString() + "-"+window.location.href+".json" );
};	
javascript: (function(){var t={eval:fn()},e=!0;if("object"==typeof this.artoo&&(artoo.settings.reload||(artoo.log.verbose("artoo already exists within this page. No need to inject him again."),artoo.loadSettings(t),artoo.exec(),e=!1)),e){var o=document.getElementsByTagName("body")[0];o||(o=document.createElement("body"),document.documentElement.appendChild(o));var a=document.createElement("script");console.log("artoo.js is loading..."),a.src="//medialab.github.io/artoo/public/dist/artoo-latest.min.js",a.type="text/javascript",a.id="artoo_injected_script",a.setAttribute("settings",JSON.stringify(t)),o.appendChild(a)}}).call(this);




var seo_data = {
	summary: artoo.scrapeTable('#sc-summary', { headers: 'th'}),
	title: artoo.scrapeTable('#sc-title', { headers: 'th'}),
	desc: artoo.scrapeTable('#sc-description', { headers: 'th' } ),
	keywords: artoo.scrapeTable('#sc-keywords', { headers: 'th' } ),
	headings: artoo.scrapeTable('#sc-headings', { headers: 'th' } ),
	//twophrase: { heads: artoo.scrapeTable('#sc-phrases2', { headers: 'th' } ), phrases: artoo.scrapeTable('#sc-phrases2.sc-phraseList', { headers: 'th' } ) },
	text: artoo.scrapeTable('#sc-alltext', { headers: 'th' , done: function(d){ d.forEach((i)=>{i.chars = i['Text On-page'].length; i.words = i['Text On-page'].split(' ').length; }) } } )
}; 

var SEO = seo_data;
var len = SEO.summary.length;

for( var i = 0; i < len; i++ ){
  SEO.summary[i]['Meta Desc'] = SEO.desc[i]['Meta Description'];
  SEO.summary[i]['Meta Title'] = SEO.title[i]['Title'];
  SEO.summary[i]['H2'] = SEO.headings[i]['Heading text'];
  SEO.summary[i]['H2'] = SEO.headings[i]['Heading text'].split('h2');
  var hlen = SEO.summary[i]['H2'].len;
  for( var j = 0; j < hlen; j++ ){
   	SEO.summary[i]['H2'][j] = SEO.summary[i]['H2'][j].trim();
  }
  SEO.summary[i]['H1'] = SEO.headings[i]['Heading text'].split('h2')[0].split('h1');
  SEO.summary[i]['H1'].splice(0,1);
  SEO.summary[i]['H2'].splice(0,1);
}

//console.log( JSON.stringify( SEO.summary) );
artoo.savePrettyJson( seo_data, new Date().toLocaleString() + "-"+seo_data.summary[0]["URL"]+".json" );

function run() {
	this.result = [];
    window.location = "/wp-admin/edit.php";
    this.wpScraper = { iterator: 'td.title', data: { title: { sel: 'a.row-title', method: 'text' }, url: { sel: 'span.view a', attr: 'href' }, edit: { sel: 'a.row-title', attr: 'href' } } };
    artoo.ajaxSpider(
      function(i) {
        return '/wp-admin/edit.php?paged=' + (i + 1);
      },
      {
        scrape: this.wpScraper,
        concat: true,
        limit: 3
      },
      function(data) {
        //console.log('Retrieved data:', data);
        var list = data;
        //var sc = { iterator: '#wp-word-count', data: { words: { sel: 'span.word-count', method: 'text' } } };
        //list.forEach( (i)=>{ artoo.ajaxSpider( i.edit, { scrape: sc, limit: 1 }, (data)=>{ i.words = list.words; } ) } );
        result = list;
      }
    );
};
javascript: (function(){var t={eval:run},e=!0;if("object"==typeof this.artoo&&(artoo.settings.reload||(artoo.log.verbose("artoo already exists within this page. No need to inject him again."),artoo.loadSettings(t),artoo.exec(),e=!1)),e){var o=document.getElementsByTagName("body")[0];o||(o=document.createElement("body"),document.documentElement.appendChild(o));var a=document.createElement("script");console.log("artoo.js is loading..."),a.src="//medialab.github.io/artoo/public/dist/artoo-latest.min.js",a.type="text/javascript",a.id="artoo_injected_script",a.setAttribute("settings",JSON.stringify(t)),o.appendChild(a)}}).call(this);


/* Scrape  Youtube. */
var data = artoo.scrape('li.video-list-item div.content-wrapper a', { url: function(){return $(this)[0].href;}, title: function(){return $(this)[0].title;} } );


/*
xhr = new XMLHttpRequest();
   urls = 'urls=' + urls + '&submit=Ninja+Check';
   xhr.onreadystatechange = function() { if( xhr.readyState == 4 && xhr.status == 200 ) { var seo_data = scrape_seo_data(); } };
   xhr.open('POST', 'https://www.internetmarketingninjas.com/seo-tools/seo-compare/', true);
   xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
   xhr.send( urls );
*/

var baseurl = 'http://www.lostways.org/';
var trkid = '8ec00c4c-5cce-428f-b634-e14dd200e8b5';
var tsetup = {"ct":"","ct1":"","ct2":"","tg1":"","tg2":"","tg3":"","tg4":"","tg5":"","cp":null,"cpt":null,"cp1":null,"cp2":null,"cp3":null,"cp4":null,"cp5":null,"t":null,"tv":null};
var url = '';
var jsversion = 1.0;
var events_count = 0;
var max_events = 600;
var user_is_active = true;

function trackerrr()
{
    var obj = this;

    this.baseurl = baseurl; 
	this.usetrk = trkid;
	this.ts = tsetup;
	
	this.durl = "";
    this.setCookie = function(c_name,value,exdays,domain,path)
    {
        var cstring = "";
        if(exdays)
        {
	        var exdate=new Date();
        	exdate.setDate(exdate.getDate() + exdays);
        	cstring += ";expires="+exdate.toUTCString();
        }
        
        if(domain)
        {
        	cstring += ";domain="+domain;
        }
        else
        {
        	cstring += ";domain="+window.location.host;
        }
        
        if(path)
        {
        	cstring += ";path="+path;
        }
        else
        {
        	cstring += ";path=/";
        }
        
        var c_value = escape(value) + cstring;
        document.cookie=c_name + "=" + c_value;
    };
	    
    this.getCookie = function(c_name)
    {
        var c_value = document.cookie;
        var c_start = c_value.indexOf(" " + c_name + "=");
        if (c_start == -1)
        {
            c_start = c_value.indexOf(c_name + "=");
        }
        if (c_start == -1)
        {
            c_value = null;
        }
        else
        {
            c_start = c_value.indexOf("=", c_start) + 1;
            var c_end = c_value.indexOf(";", c_start);
            if (c_end == -1)
            {
                c_end = c_value.length;
            }
            c_value = unescape(c_value.substring(c_start,c_end));
        }
        return c_value;
    };

    this.sendEvent = function(name)
    {
        var trkid = obj.getCookie("trkid");

        var data = {
            action : name,
            trkid:trkid,
            url : document.URL
        };
        
        obj.sendData(data);
    }

    this.getContentTags = function(data)
    {
    	var erlm = document.getElementsByTagName("ctrk");
    	
    	if(erlm[0])
    	{
    		data["ct"] = erlm[0].getAttribute("ct");
    		data["ct1"] = erlm[0].getAttribute("ct1");
    		data["ct2"] = erlm[0].getAttribute("ct2");
    		data["tg1"] = erlm[0].getAttribute("tg1");
    		data["tg2"] = erlm[0].getAttribute("tg2");
    		data["tg3"] = erlm[0].getAttribute("tg3");
    		data["tg4"] = erlm[0].getAttribute("tg4");
    		data["tg5"] = erlm[0].getAttribute("tg5");
    		
    		obj.setCookie("ct", data["ct"]);
    		obj.setCookie("ct1", data["ct1"]);
    		obj.setCookie("ct2", data["ct2"]);
    		obj.setCookie("tg1", data["tg1"]);
    		obj.setCookie("tg2", data["tg2"]);
    		obj.setCookie("tg3", data["tg3"]);
    		obj.setCookie("tg4", data["tg4"]);
    		obj.setCookie("tg5", data["tg5"]);
    	}
    	else
    	{
    		data["ct"] = obj.getCookie("ct");
    		data["ct1"] = obj.getCookie("ct1");
    		data["ct2"] = obj.getCookie("ct2");
    		data["tg1"] = obj.getCookie("tg1");
    		data["tg2"] = obj.getCookie("tg2");
    		data["tg3"] = obj.getCookie("tg3");
    		data["tg4"] = obj.getCookie("tg4");
    		data["tg5"] = obj.getCookie("tg5");
    	}
    	
    	return data;
    }
    
    this.getTrafficTags = function(data)
    {
    	data["cp"] = obj.getCookie("cp");
    	data["cpt"] = obj.getCookie("cpt");
    	data["cp1"] = obj.getCookie("cp1");
    	data["cp2"] = obj.getCookie("cp2");
    	data["cp3"] = obj.getCookie("cp3");
    	data["cp4"] = obj.getCookie("cp4");
    	data["cp5"] = obj.getCookie("cp5");
    	return data;
    }
    
    this.getTestTags = function(data)
    {
    	data["t"] = obj.getCookie("t");
    	data["tv"] = obj.getCookie("tv");
    	return data;
    }
    
    this.init = function()
    {
    	
        var cookie = null;
        var data = {};
		
        $(window).blur(function(){
            console.log("BLUR");
            user_is_active = false;
        });

        $(window).focus(function(){
            console.log("FOCUS");
            user_is_active = true;
        });

        $(document).bind("click",function(event)
        {

            if (!event)
            {
                var event = window.event;
            }

            var posx = 0 ;
            var posy = 0 ;

            if (event.pageX || event.pageY) 	{
                posx = event.pageX;
                posy = event.pageY;
            }
            else if (event.clientX || event.clientY) 	{
                posx = event.clientX + document.body.scrollLeft + document.documentElement.scrollLeft;
                posy = event.clientY + document.body.scrollTop + document.documentElement.scrollTop;
            }
            var trkid = obj.getCookie("trkid");

            var trackid = "";
            try{
            	var target = event.target ? event.target : event.srcElement;
            	var elm = $(target).closest("[trackid]");
            	trackid = elm.attr("trackid");
            	if(trackid == undefined || trackid == null)
            	{
            		trackid = "";
            	}
            	
            	var tracking = elm.attr("tracking");
            	if(tracking != undefined && tracking != null)
            	{
            		try{
            			eval(tracking);
            		}catch(e)
            		{
            			if(console)
            			{
            				console.log("Error in tracking code:");
            				console.log(e);
            			}
            		}
            	}
            	
            }catch(e){}
            
            var data = {
                action : "CLICK",
                trkid:trkid,
                outerWidth : window.outerWidth,
                outerHeight : window.outerHeight,
                innerWidth : window.innerWidth,
                innerHeight : window.innerHeight,
                event_pozx:posx,
                event_pozy:posy,
                event_tracking_id:trackid,
                url : document.URL
            };
            obj.sendData(data);
        });


        $(window).bind("beforeunload",function(event){
            if (!event)
            {
                var event = window.event;
            }

            var posx = 0 ;
            var posy = 0 ;

            if (event.pageX || event.pageY) 	{
                posx = event.pageX;
                posy = event.pageY;
            }
            else if (event.clientX || event.clientY) 	{
                posx = event.clientX + document.body.scrollLeft
                    + document.documentElement.scrollLeft;
                posy = event.clientY + document.body.scrollTop
                    + document.documentElement.scrollTop;
            }
            var trkid = obj.getCookie("trkid");

            var data = {
                action : "EXIT",
                trkid:trkid,
                url : document.URL
            };

            if(ext && ext.getCurrentSecond)
            {
            	data.event_tracking_id = "EXIT_TIMER";
            	data.event_tracking_parameter = Math.round(ext.getCurrentSecond());
            }
            
            obj.sendData(data);
        });
        
        setTimeout(obj.touch,10000);// 10 seconds touch interval

    };

    this.touch = function()
    {
        if(user_is_active)
        {
            var trkid = obj.getCookie("trkid");

            var data = {
                action : "PING",
                trkid:trkid,
                url : document.URL
            };

            obj.sendData(data);
        }
        setTimeout(obj.touch,10000);
        
    };

    this.sendData = function(data)
    {
        events_count++;

        if(events_count < max_events)
        {
	        try{
		        data = obj.getTestTags(data);
		        data = obj.getTrafficTags(data);
		        data = obj.getContentTags(data);
	        }catch(e)
	        {
	        	console.log(e);
	        }
        
            var data_string = [];
            for(var n in data)
            {
                // safe encodes
                // @ %40
                // * %2A
                // / %2F
                // + %2B ?
                try{
                    data_string[data_string.length] = n + "=" + escape(data[n]).replace(/\@/g,"%40").replace(/\*/g,"%2A").replace(/\//g,"%2F");
                }catch(e){}
            }

            $.ajax({
                url: obj.baseurl + "__trk.php?d=" + escape(data_string.join("&")),
                type: 'GET',
        		async: false,
        		cache: false,
        		timeout: 500 // timeout 0.5 seconds - if the server did not respond during this time move along
            }).done(function(){});
        }
    };

}
TRKKK = new trackerrr();

if(window.attachEvent)
{
	window.attachEvent("onload",function(){
		TRKKK.init();
	});
}
else
{
	window.addEventListener("load",function(){
	    TRKKK.init();
	});
}

function loadJS(url)
{
    var script = document.createElement("script");
    script.type = "text/javascript";
    script.src = url;
    document.getElementsByTagName("head")[0].appendChild(script);
}

var exiter = function()
{
	// t0 in seconds
	var obj = this;
	this.t0 = 0;
	this.next_exit;
	this.theDiv = null
	this.played = 0;
	
	this.startCounter = function()
	{
		obj.t0 = new Date().getTime()/1000;
	}
	
	this.stopCounter = function()
	{
		//
		obj.played = new Date().getTime()/1000 - obj.t0;
		obj.t0 = 0;
		// console.log(obj.played);
	}
	
	this.restartCounter = function()
	{
		obj.t0 = new Date().getTime()/1000 - obj.played;
		obj.played = 0;
		// console.log(obj.t0);
	}
	
	this.getCurrentSecond = function()
	{
		if(obj.t0 == 0)
		{
			return 0;
		}
		return new Date().getTime()/1000 - obj.t0;
	}
	
	this.getExitPopSetup = function ()
	{
		//var second = obj.getCurrentSecond()+startSecond;
	        var second = obj.getCurrentSecond();
		//console.log("second"+second);
		
		setCookie("second",second,1);
		
		
		
		if(obj.next_exit == undefined)
		{
			for(var i=0;i<exit_config.length;i++)
			{
				// send first that applies
				if(exit_config[i]["from"]<=second && (exit_config[i]["to"]>second || exit_config[i]["to"]==""))
				{
					var setup = exit_config[i];
					obj.next_exit = setup["next"];
					
					return setup;			
				}
			}
		}
		else if(obj.next_exit == false)
		{       
			return null;
		}
		else if(obj.next_exit != null)
		{
			var setup = exit_config[this.next_exit];
			this.next_exit = setup["next"];
			
			return setup;
		}
		
		// default if none found - missconfiguration!
		return exit_config[0];
	}
	
	this.setCookie = function (c_name,value,exdays)
	{
	    var exdate=new Date();
	    exdate.setDate(exdate.getDate() + exdays);
	    var c_value=escape(value) + ((exdays==null) ? "" : "; expires="+exdate.toUTCString());
	    document.cookie=c_name + "=" + c_value;
	}
	
	this.getCookie = function (c_name)
	{
	    var c_value = document.cookie;
	    var c_start = c_value.indexOf(" " + c_name + "=");
	    if (c_start == -1)
	    {
	        c_start = c_value.indexOf(c_name + "=");
	    }
	    if (c_start == -1)
	    {
	        c_value = null;
	    }
	    else
	    {
	        c_start = c_value.indexOf("=", c_start) + 1;
	        var c_end = c_value.indexOf(";", c_start);
	        if (c_end == -1)
	        {
	            c_end = c_value.length;
	        }
	        c_value = unescape(c_value.substring(c_start,c_end));
	    }
	    return c_value;
	}
	
	this.DisplayPop = function (e) {
		
		if (StopExit == false) {
	        window.scrollTo(0, 0);
	        // StopExit = true;
	        // window.onbeforeunload = UnPopIt;
	        var divtag = document.createElement("div");
	        $(divtag).css({
	            position : "absolute",
	            width : "100%",
	            height : "100%",
	            zIndex : "99",
	            left : "0px",
	            top : "0px"
	        });
	        var setup = obj.getExitPopSetup();
	        
	        if(setup != null)
	        {
	        	obj.theDiv = '<div style="display:block; width:100%; height:100%; position:absolute; background:#FFFFFF; margin-top:0px; margin-left:0px;" align="center">';
	        	obj.theDiv += '<iframe src="' + setup["link"] + "?split=" + split + '" width="100%" height="100%" align="middle" frameborder="0"></iframe>';
	        	obj.theDiv += '</div>';
		        
		        $(divtag).html(obj.theDiv);
		        
		        $(document.body).css({
		            "margin":"0px",
		            "overflow":"hidden"
		        })
		        $(document.body).html(divtag);
		        console.log(setup["message"]);
		        
		        e = e || window.event;
		        if (e)
		            e.returnValue = setup["message"];
		        
		        return setup["message"];
	        }
	    }
	}
}

var ext = new exiter();
getCookie = ext.getCookie;
setCookie = ext.setCookie;

function addListener(name,func)
{
	if(window.attachEvent)
	{
		window.attachEvent("on" + name,func);
	}
	else
	{
		window.addEventListener(name,func);
	}
}

if(window.parent == window)
{
	addListener("load",function(){
		addListener("beforeunload",ext.DisplayPop);
	});
}


///////// NODE CODE ///
var artoo = require('artoo-js'),
    cheerio = require('cheerio'),
    https = require('https');

var result = {};
var totals = [];

urls = [
  "https://www.google.com/search?q=zuchon+teddybear",
  "https://www.google.com/search?q=yorkshire+terrier",
  "https://www.google.com/search?q=yorkiepoo",
  "https://www.google.com/search?q=westiepoo",
  "https://www.google.com/search?q=west+highland+white+terrier",
  "https://www.google.com/search?q=toy+poodle",
  "https://www.google.com/search?q=standard+poodle",
  "https://www.google.com/search?q=soft+coated+wheaten+terrier",
  "https://www.google.com/search?q=shorkie",
  "https://www.google.com/search?q=shih+tzu",
  "https://www.google.com/search?q=shih+poo",
  "https://www.google.com/search?q=shiba+inu",
  "https://www.google.com/search?q=schnoodle",
  "https://www.google.com/search?q=saint+bernard",
  "https://www.google.com/search?q=rottweiler",
  "https://www.google.com/search?q=puggle",
  "https://www.google.com/search?q=pomapoo",
  "https://www.google.com/search?q=pekingese",
  "https://www.google.com/search?q=peketese",
  "https://www.google.com/search?q=papitese",
  "https://www.google.com/search?q=papillon",
  "https://www.google.com/search?q=old+english+bulldogge",
  "https://www.google.com/search?q=newfoundland",
  "https://www.google.com/search?q=mini+labradoodle",
  "https://www.google.com/search?q=miniature+schnauzer",
  "https://www.google.com/search?q=miniature+poodle",
  "https://www.google.com/search?q=miniature+pinscher",
  "https://www.google.com/search?q=miniature+bulldog",
  "https://www.google.com/search?q=maltipoo",
  "https://www.google.com/search?q=maltese",
  "https://www.google.com/search?q=malteagle",
  "https://www.google.com/search?q=malchi",
  "https://www.google.com/search?q=labradoodle",
  "https://www.google.com/search?q=jack+russell+terrier",
  "https://www.google.com/search?q=havashi",
  "https://www.google.com/search?q=havanese",
  "https://www.google.com/search?q=havachon",
  "https://www.google.com/search?q=great+dane",
  "https://www.google.com/search?q=goldendoodle",
  "https://www.google.com/search?q=german+shepherd+dog",
  "https://www.google.com/search?q=freagle",
  "https://www.google.com/search?q=dogue+de+bordeaux+french+mastiff",
  "https://www.google.com/search?q=dalmatian",
  "https://www.google.com/search?q=dachshund",
  "https://www.google.com/search?q=cocker+spaniel",
  "https://www.google.com/search?q=cockapoo",
  "https://www.google.com/search?q=chow+chow",
  "https://www.google.com/search?q=chinese+crested",
  "https://www.google.com/search?q=cavalier+king+charles",
  "https://www.google.com/search?q=cairn+terrier",
  "https://www.google.com/search?q=bull+pug",
  "https://www.google.com/search?q=brussels+griffon",
  "https://www.google.com/search?q=boxer",
  "https://www.google.com/search?q=boston+terrier",
  "https://www.google.com/search?q=boggle",
  "https://www.google.com/search?q=biewer+terrier",
  "https://www.google.com/search?q=bernese+mountain+dog",
  "https://www.google.com/search?q=bea+tzu",
  "https://www.google.com/search?q=basset+hound",
  "https://www.google.com/search?q=australian+shepherd",
  "https://www.google.com/search?q=australian+cattle",
  "https://www.google.com/search?q=aussieton",
  "https://www.google.com/search?q=aussiepoo",
  "https://www.google.com/search?q=american+bulldog"
  ];

urls.forEach( c => fetch( c, process ) );

var process = function(text) {
  var $ = cheerio.load(text);
  // Setting artoo's context
  artoo.setContext($);
  //let params = {str:'div', param:{ title: 'href', url: 'text' } );
  /*
  let params = {str:'td.title:nth-child(3)', param:{
      title: {sel: 'a'},
      url: {sel: 'a', attr: 'href'}
    }
  }
  */
  let params = {
    str:'div.g',
    param: { 
      g_url: {sel: 'h3.r a', attr: 'href'},
      cite_url: {sel: 'cite'},
      title: function() { return $(this).text(); },
    }
  };
  
  result = artoo.scrape(params.str, params.param);
  totals = totals.concat( result );
  //console.log( result );
};

var fetch = function( url, callback ){
  https.get( url, res => {
    res.setEncoding("utf8");
    let body = "";
    res.on('data', data => {
      body += data;
    });
    res.on('end', () => {
      //console.log( "done with fetch" );
      //console.log( body );
      //process(body);
      callback(body);
    });
  });
}


///////////////////////////////

/*$(function(){
    $( ".chart" ).each(function( index ) {
        var dofollow = parseInt($(this).attr("data-dofollow"));
        var fk = dofollow/(dofollow+parseInt($(this).attr("data-nofollow")))*100;
        var culoarea = "#02B3E7";
        
        if (fk>=0 && fk<=29) {
            culoarea = '#ff0000';
        } else if (fk>=30 && fk<=49) {
            culoarea = '#ff5500';
        } else if (fk>=50 && fk<=59) {
            culoarea = '#ffc600';
        } else if (fk>=60 && fk<=69) {
            culoarea = '#FFC700';
        } else if (fk>=70 && fk<=79) {
            culoarea = '#bbf700';
        } else if (fk>=80 && fk<=89) {
            culoarea = '#5ac900';
        } else if (fk>=90 && fk<=100) {
            culoarea = '#009b1f';
        }
        
      $(this).drawPieChart([
        { title: "Dofollow", value: dofollow,  color: culoarea },
        { title: "Nofollow", value:  parseInt($(this).attr("data-nofollow")),   color: "#CFD3D6" }
      ]);
    });
});*/

;(function($, undefined) {
  $.fn.drawPieChart = function(data, options) {
    var $this = this,
      W = $this.width(),
      H = $this.height(),
      centerX = W/2,
      centerY = H/2,
      cos = Math.cos,
      sin = Math.sin,
      PI = Math.PI,
      settings = $.extend({
        segmentShowStroke : true,
        segmentStrokeColor : "#fff",
        segmentStrokeWidth : 1,
        baseColor: "transparent",
        baseOffset: 10,
        edgeOffset: 10,//offset from edge of $this
        pieSegmentGroupClass: "pieSegmentGroup",
        pieSegmentClass: "pieSegment",
        lightPiesOffset: 3,//lighten pie's width
        lightPiesOpacity: .3,//lighten pie's default opacity
        lightPieClass: "lightPie",
        animation : true,
        animationSteps : 90,
        animationEasing : "easeInOutExpo",
        tipOffsetX: -8,
        tipOffsetY: -35,
        tipClass: "pieTip",
        beforeDraw: function(){  },
        afterDrawed : function(){  },
        onPieMouseenter : function(e,data){  },
        onPieMouseleave : function(e,data){  },
        onPieClick : function(e,data){  }
      }, options),
      animationOptions = {
        linear : function (t){
          return t;
        },
        easeInOutExpo: function (t) {
          var v = t<.5 ? 8*t*t*t*t : 1-8*(--t)*t*t*t;
          return (v>1) ? 1 : v;
        }
      },
      requestAnimFrame = function(){
        return window.requestAnimationFrame ||
          window.webkitRequestAnimationFrame ||
          window.mozRequestAnimationFrame ||
          window.oRequestAnimationFrame ||
          window.msRequestAnimationFrame ||
          function(callback) {
            window.setTimeout(callback, 1000 / 60);
          };
      }();

    var $wrapper = $('<svg width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"></svg>').appendTo($this);
    var $groups = [],
        $pies = [],
        $lightPies = [],
        easingFunction = animationOptions[settings.animationEasing],
        pieRadius = Min([H/2,W/2]) - settings.edgeOffset,
        segmentTotal = 0;

    //Draw base circle
    var drawBasePie = function(){
      var base = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      var $base = $(base).appendTo($wrapper);
      base.setAttribute("cx", centerX);
      base.setAttribute("cy", centerY);
      base.setAttribute("r", pieRadius+settings.baseOffset);
      base.setAttribute("fill", settings.baseColor);
    }();

    //Set up pie segments wrapper
    var pathGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    var $pathGroup = $(pathGroup).appendTo($wrapper);
    $pathGroup[0].setAttribute("opacity",0);

    //Set up tooltip
    var $tip = $('<div class="' + settings.tipClass + '" />').appendTo('body').hide(),
      tipW = $tip.width(),
      tipH = $tip.height();

    for (var i = 0, len = data.length; i < len; i++){
      segmentTotal += data[i].value;
      var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute("data-order", i);
      g.setAttribute("class", settings.pieSegmentGroupClass);
      $groups[i] = $(g).appendTo($pathGroup);
      $groups[i]
        .on("mouseenter", pathMouseEnter)
        .on("mouseleave", pathMouseLeave)
        .on("mousemove", pathMouseMove)
        .on("click", pathClick);

      var p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      p.setAttribute("stroke-width", settings.segmentStrokeWidth);
      p.setAttribute("stroke", settings.segmentStrokeColor);
      p.setAttribute("stroke-miterlimit", 2);
      p.setAttribute("fill", data[i].color);
      p.setAttribute("class", settings.pieSegmentClass);
      $pies[i] = $(p).appendTo($groups[i]);

      var lp = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      lp.setAttribute("stroke-width", settings.segmentStrokeWidth);
      lp.setAttribute("stroke", settings.segmentStrokeColor);
      lp.setAttribute("stroke-miterlimit", 2);
      lp.setAttribute("fill", data[i].color);
      lp.setAttribute("opacity", settings.lightPiesOpacity);
      lp.setAttribute("class", settings.lightPieClass);
      $lightPies[i] = $(lp).appendTo($groups[i]);
    }

    settings.beforeDraw.call($this);
    //Animation start
    triggerAnimation();

    function pathMouseEnter(e){
      var index = $(this).data().order;
      $tip.text(data[index].title + ": " + data[index].value).fadeIn(100);
      if ($groups[index][0].getAttribute("data-active") !== "active"){
        $lightPies[index].animate({opacity: .8}, 180);
      }
      settings.onPieMouseenter.apply($(this),[e,data]);
    }
    function pathMouseLeave(e){
      var index = $(this).data().order;
      $tip.hide();
      if ($groups[index][0].getAttribute("data-active") !== "active"){
        $lightPies[index].animate({opacity: settings.lightPiesOpacity}, 100);
      }
      settings.onPieMouseleave.apply($(this),[e,data]);
    }
    function pathMouseMove(e){
      $tip.css({
        top: e.pageY + settings.tipOffsetY,
        left: e.pageX - $tip.width() / 2 + settings.tipOffsetX
      });
    }
    function pathClick(e){
      var index = $(this).data().order;
      var targetGroup = $groups[index][0];
      for (var i = 0, len = data.length; i < len; i++){
        if (i === index) continue;
        $groups[i][0].setAttribute("data-active","");
        $lightPies[i].css({opacity: settings.lightPiesOpacity});
      }
      if (targetGroup.getAttribute("data-active") === "active"){
        targetGroup.setAttribute("data-active","");
        $lightPies[index].css({opacity: .8});
      } else {
        targetGroup.setAttribute("data-active","active");
        $lightPies[index].css({opacity: 1});
      }
      settings.onPieClick.apply($(this),[e,data]);
    }
    function drawPieSegments (animationDecimal){
      var startRadius = -PI/2,//-90 degree
          rotateAnimation = 1;
      if (settings.animation) {
        rotateAnimation = animationDecimal;//count up between0~1
      }

      $pathGroup[0].setAttribute("opacity",animationDecimal);

      //draw each path
      for (var i = 0, len = data.length; i < len; i++){
        var segmentAngle = rotateAnimation * ((data[i].value/segmentTotal) * (PI*2)),//start radian
            endRadius = startRadius + segmentAngle,
            largeArc = ((endRadius - startRadius) % (PI * 2)) > PI ? 1 : 0,
            startX = centerX + cos(startRadius) * pieRadius,
            startY = centerY + sin(startRadius) * pieRadius,
            endX = centerX + cos(endRadius) * pieRadius,
            endY = centerY + sin(endRadius) * pieRadius,
            startX2 = centerX + cos(startRadius) * (pieRadius + settings.lightPiesOffset),
            startY2 = centerY + sin(startRadius) * (pieRadius + settings.lightPiesOffset),
            endX2 = centerX + cos(endRadius) * (pieRadius + settings.lightPiesOffset),
            endY2 = centerY + sin(endRadius) * (pieRadius + settings.lightPiesOffset);
        var cmd = [
          'M', startX, startY,//Move pointer
          'A', pieRadius, pieRadius, 0, largeArc, 1, endX, endY,//Draw outer arc path
          'L', centerX, centerY,//Draw line to the center.
          'Z'//Cloth path
        ];
        var cmd2 = [
          'M', startX2, startY2,
          'A', pieRadius + settings.lightPiesOffset, pieRadius + settings.lightPiesOffset, 0, largeArc, 1, endX2, endY2,//Draw outer arc path
          'L', centerX, centerY,
          'Z'
        ];
        $pies[i][0].setAttribute("d",cmd.join(' '));
        $lightPies[i][0].setAttribute("d", cmd2.join(' '));
        startRadius += segmentAngle;
      }
    }

    var animFrameAmount = (settings.animation)? 1/settings.animationSteps : 1,//if settings.animationSteps is 10, animFrameAmount is 0.1
        animCount =(settings.animation)? 0 : 1;
    function triggerAnimation(){
      if (settings.animation) {
        requestAnimFrame(animationLoop);
      } else {
        drawPieSegments(1);
      }
    }
    function animationLoop(){
      animCount += animFrameAmount;//animCount start from 0, after "settings.animationSteps"-times executed, animCount reaches 1.
      drawPieSegments(easingFunction(animCount));
      if (animCount < 1){
        requestAnimFrame(arguments.callee);
      } else {
        settings.afterDrawed.call($this);
      }
    }
    function Max(arr){
      return Math.max.apply(null, arr);
    }
    function Min(arr){
      return Math.min.apply(null, arr);
    }
    return $this;
  };
})(jQuery);

var choices = [1,3,5,7,9,11,13,15];
var answers = [];

function addThem( a, b, c ) {	return a+b+c; }

for( var i = 0; i < choices.length; i++ ) {
  for( var l = 0; l < choices.length; l++ ) {
    for( var m = 0; m < choices.length; m ++ ) {
      let o = {
        val: addThem( choices[i], choices[l], choices[m] ), 
        combination: choices[i].toString() + ', ' + choices[l].toString() + ', ' + choices[m].toString()
      };
      answers.push( o );
    }
  }
}
// find one that equals 30.
a = answers.filter( i => { i.val==30 } );
console.log( a.length > 0 ? "Yes the answer is " + a.combination: "No - Take any integer k and multiply it by two; since it is multiplied by 2, it is divisible by 2, by definition any even integer is divisible by two; thus we can express any even integer as 2*(some integer lets say k) == 2(k); All odd integers are in the form of (2k+1) because if you add one more to any even integer you will get an odd integer, because it is no longer evenly divisible by 2. Now take any two integers from the list of choices we are given (which are all odd): (2n+1)+(2m+1)=2m+2n+2 = 2(m+n+1), now let m+n+1 be k, we have an integer expressed as 2(k) which must be even, therefore any sum of any of the two choices will be even; now since we need to take any other integer from this list... which again, is always going to be odd; we have even + odd or 2n+(2m+1)=2n+2m+1=2(m+n)+1; which is in the form of (2k+1), and is therefore odd; Since the sought after answer is 30 and 30 can be expressed as 2(15), it is even; Now since the answer is even and we need the sum of an even and an odd, there will never be a case where the sum of 3 odd numbers makes our even number 30. So no, we cannot answer this question. But if you dont believe me still you can brute force the question with this JS code: " );

function getPageWordCount( url ){
	xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function() { 
		if( xhr.readyState == 4 && xhr.status == 200 ){
			// do something with the result.
			console.log( xhr.response );
		}
	}

	xhr.open( 'POST', "https://wordcounter.net/website-word-count" , true );
	var payload = "url=" + encodeURI( url) + "&submit=Count+Words";
	xhr.setRequestHeader( "Content-type", "application/x-www-form-urlencoded" );
	xhr.send( payload );

}
res.forEach( (e,i,a) => {
  getPageWordCount( e.g_url );
} );

function getBySignature( text, start, end ) {
  let result = "";
  //text.find( start ).get
  return result;
}
