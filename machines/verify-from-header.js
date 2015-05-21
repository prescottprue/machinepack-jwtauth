module.exports = {


  friendlyName: 'Verify From Header',


  description: 'Verify a token that is provided in a request header.',
  
  extendedDescription: 'Use a provided secret to decode a JSON web token coming from a request header. You may choose what algorithm you want to use to decode the JWT, but make sure to use the same algorithm that you used to encode the JWT.',

  environment: ['req'],

  inputs: {
    header: {
      friendlyName: 'Header Name',
      example:'Authorization',
      description:'The name/key of the header from which to get the token string.',
      required: true
    },
    secret: {
      friendlyName: 'Secret',
      example: 'abc123jdhs3h4js',
      description: 'Secret used to decode the JSON web token.',
      required: true
    },
    schema:{
      friendlyName: 'Schema',
      typeclass:'*',
      description:'Example of expected token object to make available in output. Can be example object or a list/array of parameter names.'
    },
    headerPrefix:{
      friendlyName: 'Prefix'
      example: 'Bearer ',
      description: 'Prefix attached to token within header value. This is only nessesary if you have set a prefix within the request.'
    },
    algorithm:{
      friendlyName: 'Algorithm',
      example:'HS256',
      description:'The type of algorithm that is used to decode the JWT. Options: HS256, HS384, HS512 and RS256. Make sure to use the same algorithm that you used to encode the JWT.'
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
      hasDynamicOutputType:true,
      getExample:function (inputs){
        // Example schema
        var defaultObj = {id:"abc123", email:"example@example.com", role:"user", sessionId:"abc123"};
        if(!inputs.schema) return defaultObj;
        // Handle a array of parameters
        if(_.isArray(inputs.schema)){
          return arrayToExample(inputs.schema);
        }
        // Handle a list of parameters
        if(_.isString(inputs.schema)){
          var paramsArray = inputs.schema.split(",");
          return arrayToExample(paramsArray);
        }
        // schema is an object
        return inputs.schema;
      }
    }
  },


  fn: function (inputs, exits, env) {
    var jwtMachine = require('machinepack-jwt');

    var headerVal = env.req.get(inputs.header);
    var decodeParams = {secret:inputs.secret};

    if(headerVal){ //Check that value exists for header
      if(inputs.algorithm){ //Add algorithm if it exists
        decodeParams.algorithm = inputs.algorithm;
      }
      if(inputs.headerPrefix){ //Remove prefix from header if headerPrefix exists
        headerVal.replace(inputs.headerPrefix, ""); //Remove prefix to leave token string
        decodeParams.token = headerVal;
      }
      try{
        return exits.success(jwtMachine.decode(decodeParams));
      } catch(err){
        return exits.error(err);
      }
    }
    return exits.nullHeader(); //Header does not exist
  },

};
