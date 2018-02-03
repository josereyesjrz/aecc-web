#Generate token
@app.route("/client_token", methods=["GET"])
def client_token():
	return braintree.ClientToken.generate()

@app.route("/checkout", methods=["POST"])
def create_purchase():
	nonce_from_the_client = request.form["payment_method_nonce"]
	#Use payment method nonce here...

@app.route('/checkouts/new', methods=['GET'])
def new_checkout():
   client_token = braintree.ClientToken.generate()
   return render_template('checkouts/new.html', client_token=client_token)

@app.route('/checkouts/<transaction_id>', methods=['GET'])
def show_checkout(transaction_id):
   transaction = braintree.Transaction.find(transaction_id)
   result = {}
   if transaction.status in TRANSACTION_SUCCESS_STATUSES:
       result = {
           'header': 'Sweet Success!',
           'icon': 'success',
           'message': 'Your test transaction has been successfully processed. See the Braintree API response and try again.'
       }
   else:
       result = {
           'header': 'Transaction Failed',
           'icon': 'fail',
           'message': 'Your test transaction has a status of ' + transaction.status + '. See the Braintree API response and try again.'
       }

   return render_template('checkouts/show.html', transaction=transaction, result=result)

@app.route('/checkouts', methods=['POST'])
def create_checkout():
   result = braintree.Transaction.sale({
       'amount': request.form['amount'],
       'payment_method_nonce': request.form['payment_method_nonce'],
       'options': {
           "submit_for_settlement": True
       }
   })

   if result.is_success or result.transaction:
       return redirect(url_for('show_checkout',transaction_id=result.transaction.id))
   else:
       for x in result.errors.deep_errors: flash('Error: %s: %s' % (x.code, x.message))
       return redirect(url_for('new_checkout'))