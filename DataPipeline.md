dataModels.py will contain the format for all the events we'll be using.
Since we're using two inputs (dnsMasq and tshark), we'll need to take both inputs and try normalise them.
    So, we'll use tshark_capture.py to stream the data from tshark, dnsmasq_capture.py to stream the data from dnsmasq.
> Since that's two input streams, we'll need to combine them. For ease of naming, I'll just call it capture_combo.py.

Then, the output of capture_combo.py gets parsed and broken down to the specific parts to create a DNSEvent.
