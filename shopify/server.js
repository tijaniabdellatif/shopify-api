
require('dotenv').config();
const express=require('express');
const app = express();


const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();

const querystring = require('querystring');
const request = require('request-promise');
const API_KEY = process.env.API_KEY;
const SECRET = process.env.SECRET;
const PORT = process.env.PORT || 3000;

const scopes = 'write_products';
const DNSAddress = 'https://5241-160-179-48-110.ngrok.io';

app.get('/tamaro',(req,res) => {

      const shop = req.query.shop;

      if(shop){
        const state = nonce();
        console.log(state);
           
            const redirectURI = DNSAddress + '/tamaro/edi'
            const installURL = 'https://'+shop+'/admin/oauth/authorize?client_id='+API_KEY+'&scope='+scopes+'&state='+state+'&redirect_uri='+redirectURI
            res.cookie("state",state);
            res.redirect(installURL);

      }else {

        return res.status(400).send('Missing shop param. Please add your queryParametre like this ?shop=address')
      }
})


app.get('/tamaro/edi',(req,res) => {

    const {shop,hmac,code,state} = req.query
    const stateCookie = cookie.parse(req.headers.cookie).state;

    console.log((state))

    if(state !== stateCookie){

        return res.status(403).send('Request origin cannot be verified');
    }

    if(shop && hmac && code){

          const map = Object.assign({},req.query);
          delete map['hmac'];
          const message = querystring.stringify(map);
          const generatedHash = crypto.createHmac('sha256',SECRET).update(message).digest('hex');



        if(generatedHash !== hmac){

            return res.status(400).send('Something is wrong with your hmac')
        }

        res.status(200).send('verification validated');
        const accessTokenRequestUrl = `https://${shop}/admin/oauth/access_token`;
        const payload = {

              client_id:API_KEY,
              client_secret:SECRET,
              code
        };

    }else {


          res.status(400).send('required params missing');

    }
})

app.listen(PORT,() => {

     console.log('the app is running on :  ',PORT);
})