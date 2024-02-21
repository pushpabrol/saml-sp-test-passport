const express = require('express');
const session = require('express-session');
const passport = require('passport');
const bodyParser = require('body-parser');
const fs = require('fs');
const xml2js = require('xml2js');
const SamlStrategy = require('passport-saml').Strategy;
const axios = require('axios');


const htmlHead = `
<head>
  <title>Login with SAML IDP</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; }
    pre { background-color: #f4f4f4; padding: 10px; }
    form { margin-bottom: 20px; }
    label { display: block; margin-bottom: 8px; }
    .container { margin-bottom: 20px; }
  </style>
</head>
`;

const formatCertificate = (certData) => {
    // Ensure no line breaks or extra spaces exist within the certData
    const normalizedCertData = certData.replace(/\n/g, '').replace(/\r/g, '').replace(/ /g, '');
    // Insert line breaks every 64 characters
    const pemFormattedCert = normalizedCertData.replace(/(.{64})/g, "$1\n");
    // Wrap the formatted certificate string with the BEGIN and END tags
    return `-----BEGIN CERTIFICATE-----\n${pemFormattedCert}\n-----END CERTIFICATE-----\n`;
  };
  
// Function to parse IdP metadata and return configuration data
function parseIdPMetadata(metadataPath) {
  return new Promise((resolve, reject) => {
    //const parser = new xml2js.Parser();
    const parser = new xml2js.Parser({
        tagNameProcessors: [xml2js.processors.stripPrefix] // Strips namespace prefixes
    });
    const xml = fs.readFileSync(metadataPath, 'utf8');

    parser.parseString(xml, (err, result) => {
      if (err) {
        reject('Failed to parse IdP metadata');
        return;
      }

      try {
        const idpEntityDescriptor = result.EntityDescriptor;
        
        const idpSSODescriptor = idpEntityDescriptor.IDPSSODescriptor[0];
        console.log(idpSSODescriptor.SingleSignOnService);
        const idpSSOService = idpSSODescriptor.SingleSignOnService.find(
          service => service.$.Binding === 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
        );
        const idpSLOService = idpSSODescriptor.SingleLogoutService.find(
            service => service.$.Binding === 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
          );
          console.log("slo", idpSLOService);
        const idpCertDataFetch = idpSSODescriptor.KeyDescriptor.find(
            desc => desc.$.use === 'signing'
          )
          console.log(idpCertDataFetch);
        const idpCertData = idpSSODescriptor.KeyDescriptor.find(
          desc => desc.$.use === 'signing'
        )["KeyInfo"][0]['X509Data'][0]["X509Certificate"][0];
        

        // Format certificate to PEM format
        const idpCert = formatCertificate(idpCertData);
        
        fs.writeFile("./cert-entra.pem", idpCert, (err) => {
            if (err) {
              console.error('Failed to write the certificate to file:', err);
            } else {
              console.log(`Certificate was successfully written`);
            }
          });
        console.log(idpSSOService);
        resolve({
          entryPoint: idpSSOService.$.Location,
          cert: idpCert,
          logoutEndpoint : idpSLOService.$.Location
        });
      } catch (parseError) {
        console.log(parseError);
        reject('Error processing IdP metadata');
      }
    });
  });
}



  async function getTokenWithAssertion(grantType, assertion) {
    const url = 'https://pushp-dev.desmaximus.com/oauth/token';
  
    // Prepare the data as form-urlencoded
    const params = new URLSearchParams();
    params.append('grant_type', grantType);
    params.append('assertion', assertion);
    
    // Additional parameters might be required depending on your grant type,
    // such as client_id, client_secret, or others.
    //params.append('client_id', 'YOUR_CLIENT_ID');
    // Uncomment and replace YOUR_CLIENT_SECRET with your actual client secret if needed
    // params.append('client_secret', 'YOUR_CLIENT_SECRET');
  
    try {
      const response = await axios.post(url, params.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });
  
      console.log('Token Response:', response.data);
      return response.data;
    } catch (error) {
      console.error('Error fetching token:', error.response ? error.response.data : error.message);
      throw error;
    }
  }

  

(async()=> {

const app = express();
const port = 3000;

app.use(session({
  secret: 'secret', // Replace with a real secret in production
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

// Configure body-parser to parse URL-encoded bodies and only text/plain for SAML responses
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.text({ type: 'text/xml' }));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});


const idpConfig = await parseIdPMetadata('./idp.xml');


// Configure passport-saml strategy
const samlStrategy = new SamlStrategy({
  entryPoint: idpConfig.entryPoint,
  issuer: 'my_sp_samltestid_001', // Your SP entity ID
  callbackUrl: 'http://localhost:3000/login/callback',
  cert: idpConfig.cert,
  logoutUrl : idpConfig.logoutEndpoint,
  logoutCallbackUrl: 'http://localhost:3000/logout/callback'
}, (profile, done) => {
  // Here, you can use the profile to authenticate the user in your system
  // To access the raw SAML response, you can use profile.getAssertionXml() or profile.getAssertion()
  console.log('SAML response:', profile.getAssertionXml());
  profile.assertionXmlBase64 = Buffer.from(profile.getAssertionXml()).toString('base64');
  return done(null, profile);
});

passport.use(samlStrategy);

passport.logoutSaml = function(req, res) {
    //Here add the nameID and nameIDFormat to the user if you stored it someplace.

    samlStrategy.logout(req, function(err, request){
        if(!err){
            //redirect to the IdP Logout URL
            res.redirect(request);
        }
    });
};
passport.logoutSamlCallback = function(req, res){
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
}

app.post('/logout/callback', passport.logoutSamlCallback);


app.get('/', (req, res) => {
   console.log(req.session);
    if (!req.isAuthenticated()) {
        // If raw SAML Response is not set, show a button to redirect to the login route
        res.send(`
          <html>
          ${htmlHead}
          <body>
            <p>Please click the button to log in with SAML IDP</p>
            <form action="/login" method="get">
              <button type="submit">Login with SAML IDP</button>
            </form>
          </body>
          </html>
        `);
      } else {
        // If raw SAML Response is set, show it

        res.send(`
          <html>
          ${htmlHead}
          <body>
            <pre id="json">${JSON.stringify(req.user)}</pre>
            <p>Click button to exchange SAML Assertion with token</p>
            <form action="/token-exchange" method="POST">
              <input type="hidden" name="assertion" value="${req.user.assertionXmlBase64}" />
              <button type="submit">Exchange</button>
            </form>
          </body>
          </html>
        `)
      }
});

app.get('/metadata', (req, res) => {
    res.type('application/xml');
    res.status(200).send(samlStrategy.generateServiceProviderMetadata());
  });

// Route to start SAML login
app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  (req, res) => {
    res.redirect('/');
  }
);

const captureSamlResponse = (req, res, next) => {
    if (req.body && req.body.SAMLResponse) {
      // The SAML Response is URL-encoded in the POST body, so we decode it
      const samlResponse = Buffer.from(req.body.SAMLResponse, 'base64').toString('utf-8');
      console.log('Raw SAML Response:', samlResponse);
      // Store the raw SAML Response in the session object if you need to use it later
      req.session.rawSamlResponse = req.body.SAMLResponse;

    }
    next();
  };

// Route to handle callback from IdP
app.post('/login/callback',
  //captureSamlResponse, // Capture the raw SAML Response before passport processing
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  (req, res) => {
    // At this point, you can also access req.rawSamlResponse if you stored it
    res.redirect('/');
  }
);

app.post('/token-exchange', bodyParser.urlencoded({ extended: false }), async (req, res) => {
    try {
      const assertionXmlBase64 = req.body.assertion;
      if (!assertionXmlBase64) {
        return res.status(400).send('Assertion is required');
      }

      const data = await getTokenWithAssertion('urn:ietf:params:oauth:grant-type:saml2-bearer',assertionXmlBase64);
    //   const body = {
    //     grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
    //     assertion: req.body.assertion
    // };
  
    //   // Decode the Base64-encoded SAML Assertion
    //   const assertionXml = Buffer.from(assertionXmlBase64, 'base64').toString('utf-8');
  
    //   // Assuming you have the IdP certificate in PEM format (you should fetch this securely, e.g., from environment variables or a secure store)
    //   const idpCert = idpConfig.cert; // This should be the certificate you got from parsing the metadata
  
    //   // Validate the SAML Assertion signature
    //   const isValidSignature = validateSamlAssertion(assertionXml, idpCert);
    //   if(isValidSignature) {
    //     const userData = extractDataFromSAMLAssertion(assertionXml);
    //     res.send(userData);
    //   } else res.send({ validSignature: false });
    res.send(`
    <html>
  ${htmlHead}
  <body>
    <div class="container">
      <h2>User Profile and Tokens</h2>
      <div>
        <label for="tokens"><strong>Tokens:</strong></label>
        <pre id="tokens">${JSON.stringify(data, null, 3)}</pre>
      </div>
      <div>
        <label for="profile"><strong>Profile:</strong></label>
        <pre id="profile">${JSON.stringify(req.user, null, 3)}</pre>
      </div>
      <div class="logout">
        <!-- Assuming you have a route /logout defined in your express app that handles logout logic -->
        <form action="/logout" method="POST">
          <button type="submit">Logout</button>
        </form>
      </div>
    </div>
  </body>
</html>

  `)
      //res.send(data);
      
    } catch (error) {
      console.error('Error processing token exchange:', error);
      res.status(500).send('Failed to process token exchange');
    }
  });


  app.post('/logout', (req, res) => {
    //req.logout();  // Passport.js logout method
   // res.redirect('/');  // Redirect to the home page or login page

   passport.logoutSaml(req,res);
  });

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
})();
