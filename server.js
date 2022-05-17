const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();
const querystring = require('querystring');
const request = require('request-promise');


const apiKey = process.env.SHOPIFY_API_KEY
const apiSecret =process.env.SHOPIFY_API_SECRET
const scopes ='write_products'
const forwardingAddress = process.env.TUNNEL

app.get('/dashboard', async (req, res) => {
    try {
        res.status(200).json({
            message: "welcome node app!"
        })
    } catch (error) {
        res.status(400).json({
            message: error.message
        })
    }
});

app.get('/shopify', (req, res) => {
    //shopname
    const shopName = req.query.shop;
    if (shopName) {
        const shopState = nonce();
        //callback redirect
        const redirectURL = forwardingAddress + '/shopify/callback';
        //install URL
        const shopifyURL = 'https://' + shopName +
            '/admin/oauth/authorize?client_id=' + apiKey +
            '&scope=' + scopes+
            '&state=' + shopState +
            '&redirect_uri=' + redirectURL;
        res.cookie('state', shopState);
        res.redirect(shopifyURL);
    } else {
        return res.status(400).send('Missing "Shop Name" parameter!!');
    }
});

app.get('/shopify/callback',(req,res)=>{
    const { shop: shop, hmac, code, shopState } = req.query;
    const stateCookie = cookie.parse(req.headers.cookie).state;
    
    if (shop && hmac && code) {
        const queryMap = Object.assign({}, req.query);
        delete queryMap['signature'];
        delete queryMap['hmac'];

        const message = querystring.stringify(queryMap);
        const providedHmac = Buffer.from(hmac, 'utf-8');
        const generatedHash = Buffer.from(crypto.createHmac('sha256', apiSecret).update(message).digest('hex'), 'utf-8');

        let hashEquals = false;

        try {
            hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac);
        } catch (e) {
            hashEquals = false;
        }

        if (!hashEquals) {
            return res.status(400).send('HMAC validation failed');
        }

        const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
        const accessTokenPayload = {
            client_id: apiKey,
            client_secret: apiSecret,
            code,
        };

        request.post(accessTokenRequestUrl, { json: accessTokenPayload })
            .then((accessTokenResponse) => {
                const accessToken = accessTokenResponse.access_token;
                const shopRequestURL = 'https://' + shop + '/admin/api/2020-04/shop.json';
                const shopRequestHeaders = { 'X-Shopify-Access-Token': accessToken };
                    console.log(`token - ${accessToken}`)
                request.get(shopRequestURL, { headers: shopRequestHeaders })
                    .then((shopResponse) => {
                         res.redirect('/dashboard');
                    })
                    .catch((error) => {
                        res.status(error.statusCode).send(error.error.error_description);
                    });
            })
            .catch((error) => {
                res.status(error.statusCode).send(error.error.error_description);
            });

    } else {
        res.status(400).send('Required parameters missing');
    }
})

app.listen(3000, () => console.log('Application listening on port 3000!'));
