#ifndef ZT_ROOT_GEOIP_HTML_H
#define ZT_ROOT_GEOIP_HTML_H

#define ZT_GEOIP_HTML_HEAD \
"<!DOCTYPE html>\n" \
"<html>\n" \
"  <head>\n" \
"    <meta name=\"viewport\" content=\"initial-scale=1.0, user-scalable=no\">\n" \
"    <meta charset=\"utf-8\">\n" \
"    <title>GeoIP Map</title>\n" \
"    <style>\n" \
"      #map {\n" \
"        height: 100%;\n" \
"      }\n" \
"      html, body {\n" \
"        height: 100%;\n" \
"        width: 100%;\n" \
"        margin: 0;\n" \
"        padding: 0;\n" \
"      }\n" \
"    </style>\n" \
"  </head>\n" \
"  <body>\n" \
"    <div id=\"map\"></div>\n" \
"    <script>\n" \
"\n" \
"      function initMap() {\n" \
"        var map = new google.maps.Map(document.getElementById('map'), {\n" \
"          zoom: 3\n" \
"        });\n" \
"        var markers = locations.map(function(location,i) {\n" \
"          return new google.maps.Marker({\n" \
"            position: location,\n" \
"            label: location._l\n" \
"          });\n" \
"        });\n" \
"\n" \
"        var markerCluster = new MarkerClusterer(map,markers,{imagePath: 'https://developers.google.com/maps/documentation/javascript/examples/markerclusterer/m'});\n" \
"      }\n" \
"      var locations = ["

#define ZT_GEOIP_HTML_TAIL \
"];\n" \
"    </script>\n" \
"    <script src=\"https://developers.google.com/maps/documentation/javascript/examples/markerclusterer/markerclusterer.js\">\n" \
"    </script>\n" \
"    <script async defer\n" \
"    src=\"https://maps.googleapis.com/maps/api/js?v=3.exp&sensor=false&callback=initMap\">\n" \
"    </script>\n" \
"  </body>\n" \
"</html>"

#endif
