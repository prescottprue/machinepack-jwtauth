module.exports = {


  friendlyName: 'Verify From Header',


  description: 'Verify a token that is provided in a request header.',
  
  extendedDescription: 'Use a provided secret to decode a JSON web token coming from a request header. You may choose what algorithm you want to use to decode the JWT, but make sure to use the same algorithm that you used to encode the JWT.',

  environment: ['req'],

  inputs: {
    header: {
      example:'Authorization',
      description:'The name/key of the header from which to get the token string.',
      required: true
    },
    secret: {
      example: 'abc123jdhs3h4js',
      description: 'Secret used to decode the JSON web token.',
      required: true
    },
    algorithm:{
      example:'HS256',
      description:'The type of algorithm that is used to decode the JWT. Options: HS256, HS384, HS512 and RS256. Make sure to use the same algorithm that you used to encode the JWT.'
    },
    headerPrefix:{
      example: 'Bearer ',
      description: 'Prefix attached to token within header value. This is only nessesary if you have set a prefix within the request.'
    }
  },

  defaultExit: 'success',

  exits: {
    error: {
      description: 'Unexpected error occurred while decoding JWT.',
    },
    nullHeader:{
      description: 'No header with that name present on request.'
    },
    success: {
      description: 'Token decoded successfully from header.',
      example:{
        email:"test@test.com", 
        name:"test"
      },
      hasDynamicOutputType:true
    }

  },


  fn: function (inputs, exits, env) {
    var jwtMachine = require('machinepack-jwt');
    
    var headerVal = env.req.get(inputs.header);

    if(headerVal){
      if(inputs.headerPrefix){
        headerVal.replace(inputs.headerPrefix, ""); //Remove prefix to leave token string
      }
      try{
        t = jwtMachine.decode({secret:inputs.secret, token:headerVal});
      } catch(err){
        exits.error(err);
      }
      return exits.success(t);
    }
    return exits.nullHeader(); //Header does not exist
  },



};
