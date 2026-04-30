[withsecure_epp_input://<name>]
client_id = <string>
* OAuth2 Client ID from the WithSecure Elements management portal.
* Required.

client_secret = <password>
* OAuth2 Client Secret (stored encrypted via Splunk's credential store).
* Required.

org_id = <string>
* WithSecure Elements Organization UUID.
* Required.

interval = <integer>
* Poll interval in seconds. Default: 300.

index = <string>
* Splunk index to write events to. Default: main.


[withsecure_bcd_input://<name>]
client_id = <string>
* OAuth2 Client ID from the WithSecure Elements management portal.
* Required.

client_secret = <password>
* OAuth2 Client Secret (stored encrypted via Splunk's credential store).
* Required.

org_id = <string>
* WithSecure Elements Organization UUID.
* Required.

risk_level_filter = <string>
* Comma-separated risk levels to collect: low,medium,high,critical.
* Leave blank to collect all risk levels.
* Optional.

auto_fetch_detections = <string>
* Set to 'true' to fetch and index all individual detections for each new
* BCD incident (sourcetype=withsecure:epp:bcd_detection).
* Accepted values: true, false. Default: false.

interval = <integer>
* Poll interval in seconds. Default: 300.

index = <string>
* Splunk index to write events to. Default: main.

