	/**
	 * jQuery MD5 hash algorithm function
	 * 
	 * 	<code>
	 * 		Calculate the md5 hash of a String 
	 * 		String $.md5 ( String str )
	 * 	</code>
	 * 
	 * Calculates the MD5 hash of str using the Â» RSA Data Security, Inc. MD5 Message-Digest Algorithm, and returns that hash. 
	 * MD5 (Message-Digest algorithm 5) is a widely-used cryptographic hash function with a 128-bit hash value. MD5 has been employed in a wide variety of security applications, and is also commonly used to check the integrity of data. The generated hash is also non-reversable. Data cannot be retrieved from the message digest, the digest uniquely identifies the data.
	 * MD5 was developed by Professor Ronald L. Rivest in 1994. Its 128 bit (16 byte) message digest makes it a faster implementation than SHA-1.
	 * This script is used to process a variable length message into a fixed-length output of 128 bits using the MD5 algorithm. It is fully compatible with UTF-8 encoding. It is very useful when u want to transfer encrypted passwords over the internet. If you plan using UTF-8 encoding in your project don't forget to set the page encoding to UTF-8 (Content-Type meta tag). 
	 * This function orginally get from the WebToolkit and rewrite for using as the jQuery plugin.
	 * 
	 * Example
	 * 	Code
	 * 		<code>
	 * 			$.md5("I'm Persian."); 
	 * 		</code>
	 * 	Result
	 * 		<code>
	 * 			"b8c901d0f02223f9761016cfff9d68df"
	 * 		</code>
	 * 
	 * @alias Muhammad Hussein Fattahizadeh < muhammad [AT] semnanweb [DOT] com >
	 * @link http://www.semnanweb.com/jquery-plugin/md5.html
	 * @see http://www.webtoolkit.info/
	 * @license http://www.gnu.org/licenses/gpl.html [GNU General Public License]
	 * @param {jQuery} {md5:function(string))
	 * @return string
	 */
	
	(function($){
		
		var rotateLeft = function(lValue, iShiftBits) {
			return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
		}
		
		var addUnsigned = function(lX, lY) {
			var lX4, lY4, lX8, lY8, lResult;
			lX8 = (lX & 0x80000000);
			lY8 = (lY & 0x80000000);
			lX4 = (lX & 0x40000000);
			lY4 = (lY & 0x40000000);
			lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
			if (lX4 & lY4) return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
			if (lX4 | lY4) {
				if (lResult & 0x40000000) return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
				else return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
			} else {
				return (lResult ^ lX8 ^ lY8);
			}
		}
		
		var F = function(x, y, z) {
			return (x & y) | ((~ x) & z);
		}
		
		var G = function(x, y, z) {
			return (x & z) | (y & (~ z));
		}
		
		var H = function(x, y, z) {
			return (x ^ y ^ z);
		}
		
		var I = function(x, y, z) {
			return (y ^ (x | (~ z)));
		}
		
		var FF = function(a, b, c, d, x, s, ac) {
			a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
			return addUnsigned(rotateLeft(a, s), b);
		};
		
		var GG = function(a, b, c, d, x, s, ac) {
			a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
			return addUnsigned(rotateLeft(a, s), b);
		};
		
		var HH = function(a, b, c, d, x, s, ac) {
			a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
			return addUnsigned(rotateLeft(a, s), b);
		};
		
		var II = function(a, b, c, d, x, s, ac) {
			a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
			return addUnsigned(rotateLeft(a, s), b);
		};
		
		var convertToWordArray = function(string) {
			var lWordCount;
			var lMessageLength = string.length;
			var lNumberOfWordsTempOne = lMessageLength + 8;
			var lNumberOfWordsTempTwo = (lNumberOfWordsTempOne - (lNumberOfWordsTempOne % 64)) / 64;
			var lNumberOfWords = (lNumberOfWordsTempTwo + 1) * 16;
			var lWordArray = Array(lNumberOfWords - 1);
			var lBytePosition = 0;
			var lByteCount = 0;
			while (lByteCount < lMessageLength) {
				lWordCount = (lByteCount - (lByteCount % 4)) / 4;
				lBytePosition = (lByteCount % 4) * 8;
				lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
				lByteCount++;
			}
			lWordCount = (lByteCount - (lByteCount % 4)) / 4;
			lBytePosition = (lByteCount % 4) * 8;
			lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
			lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
			lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
			return lWordArray;
		};
		
		var wordToHex = function(lValue) {
			var WordToHexValue = "", WordToHexValueTemp = "", lByte, lCount;
			for (lCount = 0; lCount <= 3; lCount++) {
				lByte = (lValue >>> (lCount * 8)) & 255;
				WordToHexValueTemp = "0" + lByte.toString(16);
				WordToHexValue = WordToHexValue + WordToHexValueTemp.substr(WordToHexValueTemp.length - 2, 2);
			}
			return WordToHexValue;
		};
		
		var uTF8Encode = function(string) {
			string = string.replace(/\x0d\x0a/g, "\x0a");
			var output = "";
			for (var n = 0; n < string.length; n++) {
				var c = string.charCodeAt(n);
				if (c < 128) {
					output += String.fromCharCode(c);
				} else if ((c > 127) && (c < 2048)) {
					output += String.fromCharCode((c >> 6) | 192);
					output += String.fromCharCode((c & 63) | 128);
				} else {
					output += String.fromCharCode((c >> 12) | 224);
					output += String.fromCharCode(((c >> 6) & 63) | 128);
					output += String.fromCharCode((c & 63) | 128);
				}
			}
			return output;
		};
		
		$.extend({
			md5: function(string) {
				var x = Array();
				var k, AA, BB, CC, DD, a, b, c, d;
				var S11=7, S12=12, S13=17, S14=22;
				var S21=5, S22=9 , S23=14, S24=20;
				var S31=4, S32=11, S33=16, S34=23;
				var S41=6, S42=10, S43=15, S44=21;
				string = uTF8Encode(string);
				x = convertToWordArray(string);
				a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;
				for (k = 0; k < x.length; k += 16) {
					AA = a; BB = b; CC = c; DD = d;
					a = FF(a, b, c, d, x[k+0],  S11, 0xD76AA478);
					d = FF(d, a, b, c, x[k+1],  S12, 0xE8C7B756);
					c = FF(c, d, a, b, x[k+2],  S13, 0x242070DB);
					b = FF(b, c, d, a, x[k+3],  S14, 0xC1BDCEEE);
					a = FF(a, b, c, d, x[k+4],  S11, 0xF57C0FAF);
					d = FF(d, a, b, c, x[k+5],  S12, 0x4787C62A);
					c = FF(c, d, a, b, x[k+6],  S13, 0xA8304613);
					b = FF(b, c, d, a, x[k+7],  S14, 0xFD469501);
					a = FF(a, b, c, d, x[k+8],  S11, 0x698098D8);
					d = FF(d, a, b, c, x[k+9],  S12, 0x8B44F7AF);
					c = FF(c, d, a, b, x[k+10], S13, 0xFFFF5BB1);
					b = FF(b, c, d, a, x[k+11], S14, 0x895CD7BE);
					a = FF(a, b, c, d, x[k+12], S11, 0x6B901122);
					d = FF(d, a, b, c, x[k+13], S12, 0xFD987193);
					c = FF(c, d, a, b, x[k+14], S13, 0xA679438E);
					b = FF(b, c, d, a, x[k+15], S14, 0x49B40821);
					a = GG(a, b, c, d, x[k+1],  S21, 0xF61E2562);
					d = GG(d, a, b, c, x[k+6],  S22, 0xC040B340);
					c = GG(c, d, a, b, x[k+11], S23, 0x265E5A51);
					b = GG(b, c, d, a, x[k+0],  S24, 0xE9B6C7AA);
					a = GG(a, b, c, d, x[k+5],  S21, 0xD62F105D);
					d = GG(d, a, b, c, x[k+10], S22, 0x2441453);
					c = GG(c, d, a, b, x[k+15], S23, 0xD8A1E681);
					b = GG(b, c, d, a, x[k+4],  S24, 0xE7D3FBC8);
					a = GG(a, b, c, d, x[k+9],  S21, 0x21E1CDE6);
					d = GG(d, a, b, c, x[k+14], S22, 0xC33707D6);
					c = GG(c, d, a, b, x[k+3],  S23, 0xF4D50D87);
					b = GG(b, c, d, a, x[k+8],  S24, 0x455A14ED);
					a = GG(a, b, c, d, x[k+13], S21, 0xA9E3E905);
					d = GG(d, a, b, c, x[k+2],  S22, 0xFCEFA3F8);
					c = GG(c, d, a, b, x[k+7],  S23, 0x676F02D9);
					b = GG(b, c, d, a, x[k+12], S24, 0x8D2A4C8A);
					a = HH(a, b, c, d, x[k+5],  S31, 0xFFFA3942);
					d = HH(d, a, b, c, x[k+8],  S32, 0x8771F681);
					c = HH(c, d, a, b, x[k+11], S33, 0x6D9D6122);
					b = HH(b, c, d, a, x[k+14], S34, 0xFDE5380C);
					a = HH(a, b, c, d, x[k+1],  S31, 0xA4BEEA44);
					d = HH(d, a, b, c, x[k+4],  S32, 0x4BDECFA9);
					c = HH(c, d, a, b, x[k+7],  S33, 0xF6BB4B60);
					b = HH(b, c, d, a, x[k+10], S34, 0xBEBFBC70);
					a = HH(a, b, c, d, x[k+13], S31, 0x289B7EC6);
					d = HH(d, a, b, c, x[k+0],  S32, 0xEAA127FA);
					c = HH(c, d, a, b, x[k+3],  S33, 0xD4EF3085);
					b = HH(b, c, d, a, x[k+6],  S34, 0x4881D05);
					a = HH(a, b, c, d, x[k+9],  S31, 0xD9D4D039);
					d = HH(d, a, b, c, x[k+12], S32, 0xE6DB99E5);
					c = HH(c, d, a, b, x[k+15], S33, 0x1FA27CF8);
					b = HH(b, c, d, a, x[k+2],  S34, 0xC4AC5665);
					a = II(a, b, c, d, x[k+0],  S41, 0xF4292244);
					d = II(d, a, b, c, x[k+7],  S42, 0x432AFF97);
					c = II(c, d, a, b, x[k+14], S43, 0xAB9423A7);
					b = II(b, c, d, a, x[k+5],  S44, 0xFC93A039);
					a = II(a, b, c, d, x[k+12], S41, 0x655B59C3);
					d = II(d, a, b, c, x[k+3],  S42, 0x8F0CCC92);
					c = II(c, d, a, b, x[k+10], S43, 0xFFEFF47D);
					b = II(b, c, d, a, x[k+1],  S44, 0x85845DD1);
					a = II(a, b, c, d, x[k+8],  S41, 0x6FA87E4F);
					d = II(d, a, b, c, x[k+15], S42, 0xFE2CE6E0);
					c = II(c, d, a, b, x[k+6],  S43, 0xA3014314);
					b = II(b, c, d, a, x[k+13], S44, 0x4E0811A1);
					a = II(a, b, c, d, x[k+4],  S41, 0xF7537E82);
					d = II(d, a, b, c, x[k+11], S42, 0xBD3AF235);
					c = II(c, d, a, b, x[k+2],  S43, 0x2AD7D2BB);
					b = II(b, c, d, a, x[k+9],  S44, 0xEB86D391);
					a = addUnsigned(a, AA);
					b = addUnsigned(b, BB);
					c = addUnsigned(c, CC);
					d = addUnsigned(d, DD);
				}
				var tempValue = wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d);
				return tempValue.toLowerCase();
			}
		});
	})(jQuery);
	
	function encryptToMD5(a){ if(a=="") return a; return rstr2hex(rstr_md5(str2rstr_utf8(a)))}function hex_hmac_md5(a,b){return rstr2hex(rstr_hmac_md5(str2rstr_utf8(a),str2rstr_utf8(b)))}function md5_vm_test(){return hex_md5("abc").toLowerCase()=="900150983cd24fb0d6963f7d28e17f72"}function rstr_md5(a){return binl2rstr(binl_md5(rstr2binl(a),a.length*8))}function rstr_hmac_md5(c,f){var e=rstr2binl(c);if(e.length>16){e=binl_md5(e,c.length*8)}var a=Array(16),d=Array(16);for(var b=0;b<16;b++){a[b]=e[b]^909522486;d[b]=e[b]^1549556828}var g=binl_md5(a.concat(rstr2binl(f)),512+f.length*8);return binl2rstr(binl_md5(d.concat(g),512+128))}function rstr2hex(c){try{hexcase}catch(g){hexcase=0}var f=hexcase?"0123456789ABCDEF":"0123456789abcdef";var b="";var a;for(var d=0;d<c.length;d++){a=c.charCodeAt(d);b+=f.charAt((a>>>4)&15)+f.charAt(a&15)}return b}function str2rstr_utf8(c){var b="";var d=-1;var a,e;while(++d<c.length){a=c.charCodeAt(d);e=d+1<c.length?c.charCodeAt(d+1):0;if(55296<=a&&a<=56319&&56320<=e&&e<=57343){a=65536+((a&1023)<<10)+(e&1023);d++}if(a<=127){b+=String.fromCharCode(a)}else{if(a<=2047){b+=String.fromCharCode(192|((a>>>6)&31),128|(a&63))}else{if(a<=65535){b+=String.fromCharCode(224|((a>>>12)&15),128|((a>>>6)&63),128|(a&63))}else{if(a<=2097151){b+=String.fromCharCode(240|((a>>>18)&7),128|((a>>>12)&63),128|((a>>>6)&63),128|(a&63))}}}}}return b}function rstr2binl(b){var a=Array(b.length>>2);for(var c=0;c<a.length;c++){a[c]=0}for(var c=0;c<b.length*8;c+=8){a[c>>5]|=(b.charCodeAt(c/8)&255)<<(c%32)}return a}function binl2rstr(b){var a="";for(var c=0;c<b.length*32;c+=8){a+=String.fromCharCode((b[c>>5]>>>(c%32))&255)}return a}function binl_md5(p,k){p[k>>5]|=128<<((k)%32);p[(((k+64)>>>9)<<4)+14]=k;var o=1732584193;var n=-271733879;var m=-1732584194;var l=271733878;for(var g=0;g<p.length;g+=16){var j=o;var h=n;var f=m;var e=l;o=md5_ff(o,n,m,l,p[g+0],7,-680876936);l=md5_ff(l,o,n,m,p[g+1],12,-389564586);m=md5_ff(m,l,o,n,p[g+2],17,606105819);n=md5_ff(n,m,l,o,p[g+3],22,-1044525330);o=md5_ff(o,n,m,l,p[g+4],7,-176418897);l=md5_ff(l,o,n,m,p[g+5],12,1200080426);m=md5_ff(m,l,o,n,p[g+6],17,-1473231341);n=md5_ff(n,m,l,o,p[g+7],22,-45705983);o=md5_ff(o,n,m,l,p[g+8],7,1770035416);l=md5_ff(l,o,n,m,p[g+9],12,-1958414417);m=md5_ff(m,l,o,n,p[g+10],17,-42063);n=md5_ff(n,m,l,o,p[g+11],22,-1990404162);o=md5_ff(o,n,m,l,p[g+12],7,1804603682);l=md5_ff(l,o,n,m,p[g+13],12,-40341101);m=md5_ff(m,l,o,n,p[g+14],17,-1502002290);n=md5_ff(n,m,l,o,p[g+15],22,1236535329);o=md5_gg(o,n,m,l,p[g+1],5,-165796510);l=md5_gg(l,o,n,m,p[g+6],9,-1069501632);m=md5_gg(m,l,o,n,p[g+11],14,643717713);n=md5_gg(n,m,l,o,p[g+0],20,-373897302);o=md5_gg(o,n,m,l,p[g+5],5,-701558691);l=md5_gg(l,o,n,m,p[g+10],9,38016083);m=md5_gg(m,l,o,n,p[g+15],14,-660478335);n=md5_gg(n,m,l,o,p[g+4],20,-405537848);o=md5_gg(o,n,m,l,p[g+9],5,568446438);l=md5_gg(l,o,n,m,p[g+14],9,-1019803690);m=md5_gg(m,l,o,n,p[g+3],14,-187363961);n=md5_gg(n,m,l,o,p[g+8],20,1163531501);o=md5_gg(o,n,m,l,p[g+13],5,-1444681467);l=md5_gg(l,o,n,m,p[g+2],9,-51403784);m=md5_gg(m,l,o,n,p[g+7],14,1735328473);n=md5_gg(n,m,l,o,p[g+12],20,-1926607734);o=md5_hh(o,n,m,l,p[g+5],4,-378558);l=md5_hh(l,o,n,m,p[g+8],11,-2022574463);m=md5_hh(m,l,o,n,p[g+11],16,1839030562);n=md5_hh(n,m,l,o,p[g+14],23,-35309556);o=md5_hh(o,n,m,l,p[g+1],4,-1530992060);l=md5_hh(l,o,n,m,p[g+4],11,1272893353);m=md5_hh(m,l,o,n,p[g+7],16,-155497632);n=md5_hh(n,m,l,o,p[g+10],23,-1094730640);o=md5_hh(o,n,m,l,p[g+13],4,681279174);l=md5_hh(l,o,n,m,p[g+0],11,-358537222);m=md5_hh(m,l,o,n,p[g+3],16,-722521979);n=md5_hh(n,m,l,o,p[g+6],23,76029189);o=md5_hh(o,n,m,l,p[g+9],4,-640364487);l=md5_hh(l,o,n,m,p[g+12],11,-421815835);m=md5_hh(m,l,o,n,p[g+15],16,530742520);n=md5_hh(n,m,l,o,p[g+2],23,-995338651);o=md5_ii(o,n,m,l,p[g+0],6,-198630844);l=md5_ii(l,o,n,m,p[g+7],10,1126891415);m=md5_ii(m,l,o,n,p[g+14],15,-1416354905);n=md5_ii(n,m,l,o,p[g+5],21,-57434055);o=md5_ii(o,n,m,l,p[g+12],6,1700485571);l=md5_ii(l,o,n,m,p[g+3],10,-1894986606);m=md5_ii(m,l,o,n,p[g+10],15,-1051523);n=md5_ii(n,m,l,o,p[g+1],21,-2054922799);o=md5_ii(o,n,m,l,p[g+8],6,1873313359);l=md5_ii(l,o,n,m,p[g+15],10,-30611744);m=md5_ii(m,l,o,n,p[g+6],15,-1560198380);n=md5_ii(n,m,l,o,p[g+13],21,1309151649);o=md5_ii(o,n,m,l,p[g+4],6,-145523070);l=md5_ii(l,o,n,m,p[g+11],10,-1120210379);m=md5_ii(m,l,o,n,p[g+2],15,718787259);n=md5_ii(n,m,l,o,p[g+9],21,-343485551);o=safe_add(o,j);n=safe_add(n,h);m=safe_add(m,f);l=safe_add(l,e)}return Array(o,n,m,l)}function md5_cmn(h,e,d,c,g,f){return safe_add(bit_rol(safe_add(safe_add(e,h),safe_add(c,f)),g),d)}function md5_ff(g,f,k,j,e,i,h){return md5_cmn((f&k)|((~f)&j),g,f,e,i,h)}function md5_gg(g,f,k,j,e,i,h){return md5_cmn((f&j)|(k&(~j)),g,f,e,i,h)}function md5_hh(g,f,k,j,e,i,h){return md5_cmn(f^k^j,g,f,e,i,h)}function md5_ii(g,f,k,j,e,i,h){return md5_cmn(k^(f|(~j)),g,f,e,i,h)}function safe_add(a,d){var c=(a&65535)+(d&65535);var b=(a>>16)+(d>>16)+(c>>16);return(b<<16)|(c&65535)}function bit_rol(a,b){return(a<<b)|(a>>>(32-b))};
	
	function array(n) {  
		  for(i=0;i<n;i++) this[i]=0;  
		  this.length=n;  
		}  
		  
		  
		  
		/* Quelques fonctions fondamentales doivent ¨ºtre transform¨¦es ¨¤ cause  
		 * d'erreurs Javascript.  
		 * Essayez par exemple de calculer 0xffffffff >> 4 ...  
		 * Les fonctions utilis¨¦es maintenant sont il est vrai plus lentes que les  
		 * fonctions originales mais elles fonctionnent.  
		 */  
		  
		function integer(n) { return n%(0xffffffff+1); }  
		  
		function shr(a,b) {  
		  a=integer(a);  
		  b=integer(b);  
		  if (a-0x80000000>=0) {  
		    a=a%0x80000000;  
		    a>>=b;  
		    a+=0x40000000>>(b-1);  
		  } else  
		    a>>=b;  
		  return a;  
		}  
		  
		function shl1(a) {  
		  a=a%0x80000000;  
		  if (a&0x40000000==0x40000000)  
		  {  
		    a-=0x40000000;  
		    a*=2;  
		    a+=0x80000000;  
		  } else  
		    a*=2;  
		  return a;  
		}  
		  
		function shl(a,b) {  
		  a=integer(a);  
		  b=integer(b);  
		  for (var i=0;i<b;i++) a=shl1(a);  
		  return a;  
		}  
		  
		function and(a,b) {  
		  a=integer(a);  
		  b=integer(b);  
		  var t1=(a-0x80000000);  
		  var t2=(b-0x80000000);  
		  if (t1>=0)  
		    if (t2>=0)  
		      return ((t1&t2)+0x80000000);  
		    else  
		      return (t1&b);  
		  else  
		    if (t2>=0)  
		      return (a&t2);  
		    else  
		      return (a&b);  
		}  
		  
		function or(a,b) {  
		  a=integer(a);  
		  b=integer(b);  
		  var t1=(a-0x80000000);  
		  var t2=(b-0x80000000);  
		  if (t1>=0)  
		    if (t2>=0)  
		      return ((t1|t2)+0x80000000);  
		    else  
		      return ((t1|b)+0x80000000);  
		  else  
		    if (t2>=0)  
		      return ((a|t2)+0x80000000);  
		    else  
		      return (a|b);  
		}  
		  
		function xor(a,b) {  
		  a=integer(a);  
		  b=integer(b);  
		  var t1=(a-0x80000000);  
		  var t2=(b-0x80000000);  
		  if (t1>=0)  
		    if (t2>=0)  
		      return (t1^t2);  
		    else  
		      return ((t1^b)+0x80000000);  
		  else  
		    if (t2>=0)  
		      return ((a^t2)+0x80000000);  
		    else  
		      return (a^b);  
		}  
		  
		function not(a) {  
		  a=integer(a);  
		  return (0xffffffff-a);  
		}  
		  
		/* D¨¦but de l'algorithme */  
		  
		    var state = new array(4);  
		    var count = new array(2);  
		        count[0] = 0;  
		        count[1] = 0;  
		    var buffer = new array(64);  
		    var transformBuffer = new array(16);  
		    var digestBits = new array(16);  
		  
		    var S11 = 7;  
		    var S12 = 12;  
		    var S13 = 17;  
		    var S14 = 22;  
		    var S21 = 5;  
		    var S22 = 9;  
		    var S23 = 14;  
		    var S24 = 20;  
		    var S31 = 4;  
		    var S32 = 11;  
		    var S33 = 16;  
		    var S34 = 23;  
		    var S41 = 6;  
		    var S42 = 10;  
		    var S43 = 15;  
		    var S44 = 21;  
		  
		    function F(x,y,z) {  
		        return or(and(x,y),and(not(x),z));  
		    }  
		  
		    function G(x,y,z) {  
		        return or(and(x,z),and(y,not(z)));  
		    }  
		  
		    function H(x,y,z) {  
		        return xor(xor(x,y),z);  
		    }  
		  
		    function I(x,y,z) {  
		        return xor(y ,or(x , not(z)));  
		    }  
		  
		    function rotateLeft(a,n) {  
		        return or(shl(a, n),(shr(a,(32 - n))));  
		    }  
		  
		    function FF(a,b,c,d,x,s,ac) {  
		        a = a+F(b, c, d) + x + ac;  
		        a = rotateLeft(a, s);  
		        a = a+b;  
		        return a;  
		    }  
		  
		    function GG(a,b,c,d,x,s,ac) {  
		        a = a+G(b, c, d) +x + ac;  
		        a = rotateLeft(a, s);  
		        a = a+b;  
		        return a;  
		    }  
		  
		    function HH(a,b,c,d,x,s,ac) {  
		        a = a+H(b, c, d) + x + ac;  
		        a = rotateLeft(a, s);  
		        a = a+b;  
		        return a;  
		    }  
		  
		    function II(a,b,c,d,x,s,ac) {  
		        a = a+I(b, c, d) + x + ac;  
		        a = rotateLeft(a, s);  
		        a = a+b;  
		        return a;  
		    }  
		  
		    function transform(buf,offset) {  
		        var a=0, b=0, c=0, d=0;  
		        var x = transformBuffer;  
		  
		        a = state[0];  
		        b = state[1];  
		        c = state[2];  
		        d = state[3];  
		  
		        for (i = 0; i < 16; i++) {  
		            x[i] = and(buf[i*4+offset],0xff);  
		            for (j = 1; j < 4; j++) {  
		                x[i]+=shl(and(buf[i*4+j+offset] ,0xff), j * 8);  
		            }  
		        }  
		  
		        /* tour 1 */  
		        a = FF ( a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */  
		        d = FF ( d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */  
		        c = FF ( c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */  
		        b = FF ( b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */  
		        a = FF ( a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */  
		        d = FF ( d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */  
		        c = FF ( c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */  
		        b = FF ( b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */  
		        a = FF ( a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */  
		        d = FF ( d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */  
		        c = FF ( c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */  
		        b = FF ( b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */  
		        a = FF ( a, b, c, d, x[12], S11, 0x6b901122); /* 13 */  
		        d = FF ( d, a, b, c, x[13], S12, 0xfd987193); /* 14 */  
		        c = FF ( c, d, a, b, x[14], S13, 0xa679438e); /* 15 */  
		        b = FF ( b, c, d, a, x[15], S14, 0x49b40821); /* 16 */  
		  
		        /* tour 2 */  
		        a = GG ( a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */  
		        d = GG ( d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */  
		        c = GG ( c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */  
		        b = GG ( b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */  
		        a = GG ( a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */  
		        d = GG ( d, a, b, c, x[10], S22,  0x2441453); /* 22 */  
		        c = GG ( c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */  
		        b = GG ( b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */  
		        a = GG ( a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */  
		        d = GG ( d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */  
		        c = GG ( c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */  
		        b = GG ( b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */  
		        a = GG ( a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */  
		        d = GG ( d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */  
		        c = GG ( c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */  
		        b = GG ( b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */  
		  
		        /* tour 3 */  
		        a = HH ( a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */  
		        d = HH ( d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */  
		        c = HH ( c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */  
		        b = HH ( b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */  
		        a = HH ( a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */  
		        d = HH ( d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */  
		        c = HH ( c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */  
		        b = HH ( b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */  
		        a = HH ( a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */  
		        d = HH ( d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */  
		        c = HH ( c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */  
		        b = HH ( b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */  
		        a = HH ( a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */  
		        d = HH ( d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */  
		        c = HH ( c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */  
		        b = HH ( b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */  
		  
		        /* tour 4 */  
		        a = II ( a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */  
		        d = II ( d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */  
		        c = II ( c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */  
		        b = II ( b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */  
		        a = II ( a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */  
		        d = II ( d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */  
		        c = II ( c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */  
		        b = II ( b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */  
		        a = II ( a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */  
		        d = II ( d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */  
		        c = II ( c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */  
		        b = II ( b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */  
		        a = II ( a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */  
		        d = II ( d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */  
		        c = II ( c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */  
		        b = II ( b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */  
		  
		        state[0] +=a;  
		        state[1] +=b;  
		        state[2] +=c;  
		        state[3] +=d;  
		  
		    }  
		    /* Avec l'initialisation de  Dobbertin:  
		       state[0] = 0x12ac2375;  
		       state[1] = 0x3b341042;  
		       state[2] = 0x5f62b97c;  
		       state[3] = 0x4ba763ed;  
		       s'il y a une collision:  
		  
		       begin 644 Message1  
		       M7MH=JO6_>MG!X?!51$)W,CXV!A"=(!AR71,<X`Y-IIT9^Z&8L$2N'Y*Y:R.;  
		       39GIK9>TF$W()/MEHR%C4:G1R:Q"=  
		       `  
		       end  
		  
		       begin 644 Message2  
		       M7MH=JO6_>MG!X?!51$)W,CXV!A"=(!AR71,<X`Y-IIT9^Z&8L$2N'Y*Y:R.;  
		       39GIK9>TF$W()/MEHREC4:G1R:Q"=  
		       `  
		       end  
		    */  
		    function init() {  
		        count[0]=count[1] = 0;  
		        state[0] = 0x67452301;  
		        state[1] = 0xefcdab89;  
		        state[2] = 0x98badcfe;  
		        state[3] = 0x10325476;  
		        for (i = 0; i < digestBits.length; i++)  
		            digestBits[i] = 0;  
		    }  
		  
		    function update(b) {  
		        var index,i;  
		  
		        index = and(shr(count[0],3) , 0x3f);  
		        if (count[0]<0xffffffff-7)  
		          count[0] += 8;  
		        else {  
		          count[1]++;  
		          count[0]-=0xffffffff+1;  
		          count[0]+=8;  
		        }  
		        buffer[index] = and(b,0xff);  
		        if (index  >= 63) {  
		            transform(buffer, 0);  
		        }  
		    }  
		  
		    function finish() {  
		        var bits = new array(8);  
		        var        padding;  
		        var        i=0, index=0, padLen=0;  
		  
		        for (i = 0; i < 4; i++) {  
		            bits[i] = and(shr(count[0],(i * 8)), 0xff);  
		        }  
		        for (i = 0; i < 4; i++) {  
		            bits[i+4]=and(shr(count[1],(i * 8)), 0xff);  
		        }  
		        index = and(shr(count[0], 3) ,0x3f);  
		        padLen = (index < 56) ? (56 - index) : (120 - index);  
		        padding = new array(64);  
		        padding[0] = 0x80;  
		        for (i=0;i<padLen;i++)  
		          update(padding[i]);  
		        for (i=0;i<8;i++)  
		          update(bits[i]);  
		  
		        for (i = 0; i < 4; i++) {  
		            for (j = 0; j < 4; j++) {  
		                digestBits[i*4+j] = and(shr(state[i], (j * 8)) , 0xff);  
		            }  
		        }  
		    }  
		  
		/* Fin de l'algorithme MD5 */  
		  
		function hexa(n) {  
		 var hexa_h = "0123456789abcdef";  
		 var hexa_c="";  
		 var hexa_m=n;  
		 for (hexa_i=0;hexa_i<8;hexa_i++) {  
		   hexa_c=hexa_h.charAt(Math.abs(hexa_m)%16)+hexa_c;  
		   hexa_m=Math.floor(hexa_m/16);  
		 }  
		 return hexa_c;  
		}  
		  
		  
		var ascii="01234567890123456789012345678901" +  
		          " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"+  
		          "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";  
		  
		function MD5(message)  
		{  
		 var l,s,k,ka,kb,kc,kd;  
		  
		 init();  
		 for (k=0;k<message.length;k++) {  
		   l=message.charAt(k);  
		   update(ascii.lastIndexOf(l));  
		 }  
		 finish();  
		 ka=kb=kc=kd=0;  
		 for (i=0;i<4;i++) ka+=shl(digestBits[15-i], (i*8));  
		 for (i=4;i<8;i++) kb+=shl(digestBits[15-i], ((i-4)*8));  
		 for (i=8;i<12;i++) kc+=shl(digestBits[15-i], ((i-8)*8));  
		 for (i=12;i<16;i++) kd+=shl(digestBits[15-i], ((i-12)*8));  
		 s=hexa(kd)+hexa(kc)+hexa(kb)+hexa(ka);  
		 return s;  
		}  