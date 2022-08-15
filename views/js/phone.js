const phoneInputField = document.querySelector("#phone");
   const phoneInput = window.intlTelInput(phoneInputField, {
     utilsScript:
       "https://cdnjs.cloudflare.com/ajax/libs/intl-tel-input/17.0.8/js/utils.js",
   })
function process(event) {
 event.preventDefault();
 
 const phoneNumber = phoneInput.getNumber();
 phoneInputField.value =phoneNumber;
}1