# dxlwildfiretie
Wildfire TIE Update DXL Python Service
====================================================

Overview
--------

The Wildfire TIE DXL Python service polls the Wildfire analysis data and updates TIE over the DXL `Data Exchange Layer <http://www.mcafee.com/us/solutions/data-exchange-layer.aspx>`_ (DXL) fabric.

Here are the conditions:

**) WE NEVER SET A SCORE TO ANYTHING BEYOND UNKNOWN. TRUSTED SCORES WILL BE LEFT TO THE ENTERPRISE OWNERS 1) If TIE has a more critical rating than Wildfire, we do not change the reputation score
2) If TIE has no record of the Wildfire file, we create it in TIE and assign the score appropriately
3) If TIE has a record of the file and Wildfire reports it as being malicious, we adjust the score acording to the delta between the enterprise rating and the Wildfire rating



LICENSE
-------

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

`<http://www.apache.org/licenses/LICENSE-2.0>`_
