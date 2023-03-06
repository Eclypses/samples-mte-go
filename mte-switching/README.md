# MTE Switching Demo    

## Introduction
The MTE software allows you to use the same MTE state for the MTE Core, FLEN and MKE as long as each is initialized using the same options. A single client can switch between these based on the size of the message or other environmental needs. Below is an example that uses the MTE Core to transmit the login information and then uses the MKE to upload a file.

**IMPORTANT NOTE**
>Each side must use the same MTE "type" in a single transmission in order to decode and encode the messages; for example if the message is encoded using the MTE Core it must be decoded using the MTE Core. An exception to this rule is when using the FLEN add-on, you encode using FLEN but the decode side always uses MTE Core.

The code samples for each section show the client side using a console application, the operations on the server side are almost identical. Each section breaks out portions of the code, at the bottom of this page the full program files are also available for the client as well as the server.

## Getting Started
This sample must be run in concert with an API server. In these samples there is a C# API Server Sample you can run locally or Eclypses provides an API at https://dev-echo.eclypses.com. 

It does require the user to add their MTE libraries to the code for it to work correctly. 

This sample has been tested with MTE 3.0.x.

Follow these steps to add the MTE library and supporting files.

1. Create an mte directory.

2. Copy all files in the MTE archive directory /src/go to the local mte directory.

3. Copy the include and lib directories and all the contents to the local mte directory.

<div style="page-break-after: always; break-after: page;"></div>

## Contact Eclypses

<p align="center" style="font-weight: bold; font-size: 22pt;">For more information, please contact:</p>
<p align="center" style="font-weight: bold; font-size: 22pt;"><a href="mailto:info@eclypses.com">info@eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 22pt;"><a href="https://www.eclypses.com">www.eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 22pt;">+1.719.323.6680</p>

<p style="font-size: 8pt; margin-bottom: 0; margin: 300px 24px 30px 24px; " >
<b>All trademarks of Eclypses Inc.</b> may not be used without Eclypses Inc.'s prior written consent. No license for any use thereof has been granted without express written consent. Any unauthorized use thereof may violate copyright laws, trademark laws, privacy and publicity laws and communications regulations and statutes. The names, images and likeness of the Eclypses logo, along with all representations thereof, are valuable intellectual property assets of Eclypses, Inc. Accordingly, no party or parties, without the prior written consent of Eclypses, Inc., (which may be withheld in Eclypses' sole discretion), use or permit the use of any of the Eclypses trademarked names or logos of Eclypses, Inc. for any purpose other than as part of the address for the Premises, or use or permit the use of, for any purpose whatsoever, any image or rendering of, or any design based on, the exterior appearance or profile of the Eclypses trademarks and or logo(s).
</p>