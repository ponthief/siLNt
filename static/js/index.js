// TODO were was this needed?
// Vue.filter('reverse', function (value) {
//   // slice to make a copy of array, then reverse the copy
//   return value.slice().reverse()
// })
window.app = Vue.createApp({
  el: '#vue',
  mixins: [window.windowMixin],
  data() {
    return {
      blindbit: {
        url: '',
        user: '',
        pass: ''
      },      

      config: {sats_denominated: true},

      qrCodeDialog: {
        show: false,
        data: null
      },
      ...tables,
      ...tableData,

      walletAccounts: [],      

      showAddress: false,
      addressNote: '',
      showPayment: false,
      fetchedUtxos: false,
      utxosFilter: '',
      network: null,
      lastScanResult: null,
      showEnterSignedPsbt: false,
      signedBase64Psbt: null,      
      connectedDeviceType: null
    }
  },
  computed: {    
  },

  methods: {

    //################### PAYMENT ###################

    initPaymentData: async function () {
      if (!this.payment.show) return
      await this.refreshAddresses()
    },

    goToPaymentView: async function () {
      this.showPayment = true
      await this.initPaymentData()
    },

    //################### PSBT ###################

    updateSignedPsbt: async function (psbtBase64) {
      this.$refs.paymentRef.updateSignedPsbt(psbtBase64)
    },

    updateSignedTx: async function (txHex) {
      this.$refs.paymentRef.updateSignedTx(txHex)
    },

    showEnterSignedPsbtDialog: function () {
      this.signedBase64Psbt = ''
      this.showEnterSignedPsbt = true
    },

    checkPsbt: function () {
      this.$refs.paymentRef.updateSignedPsbt(this.signedBase64Psbt)
    },

    //################### UTXOs ###################
    scanSilentPayAddress: async function () {
      if (!this.config.blindbit_url) {
        this.$q.notify({
          type: 'warning',
          message: 'BlindBit Scan URL not configured. Open Settings to set it.',
          timeout: 10000
        })
        return
      }
      try {
        const {data} = await LNbits.api.request(
          'POST',
          '/silnt/api/v1/scan',
          this.g.user.wallets[0].inkey,
          {
            blindbit_url: this.blindbit.url,
            auth_user: this.blindbit.user,
            auth_pass: this.blindbit.pass
          }
        )

        // Map blindbit UTXOs into the utxos list
        const mappedUtxos = (data.utxos || []).map(u => ({
          txid: u.txid,          
          amount: u.amount,          
          utxo_state: u.utxo_state,
          label: u.label,
          timestamp: u.timestamp
        }))
        this.utxos.data = mappedUtxos
        this.utxos.total = mappedUtxos.filter(u => u.utxo_state === 'unspent').reduce(
          (total, u) => total + (u.amount || 0), 0
        )

        const height = data.height?.height
        this.lastScanResult = {
          utxos: mappedUtxos,
          timestamp: Date.now()
        }
        this.$q.notify({
          type: 'positive',
          message: `Scan complete. ${this.utxos.data.length} UTXO(s) found.` +
            (height ? ` Scanned to block ${height}.` : ''),
          timeout: 10000
        })
        this.tab = 'utxos'
      } catch (err) {
        this.$q.notify({
          type: 'warning',
          message: 'Failed to connect to blindbit-scan',
          timeout: 10000
        })
        LNbits.utils.notifyApiError(err)
      } finally {        
      }
    },    
    getAddressesForWallet: async function (walletId) {
      try {
        const {data} = await LNbits.api.request(
          'GET',
          '/watchonly/api/v1/addresses/' + walletId,
          this.g.user.wallets[0].inkey
        )
        return data.map(mapAddressesData)
      } catch (error) {
        this.$q.notify({
          type: 'warning',
          message: `Failed to fetch addresses for wallet with id ${walletId}.`,
          timeout: 10000
        })
        LNbits.utils.notifyApiError(error)
      }
      return []
    },    
    

    openQrCodeDialog: function (addressData) {
      this.currentAddress = addressData
      this.addressNote = addressData.note || ''
      this.showAddress = true
    },
    searchInTab: function ({tab, value}) {
      this.tab = tab
      this[`${tab}Filter`] = value
    },
    
    showAddressDetails: function (addressData) {
      this.openQrCodeDialog(addressData)
    },
    showAddressDetailsWithConfirmation: function ({addressData, wallet}) {
      this.showAddressDetails(addressData)
      if (this.$refs.serialSigner.isConnected()) {
        if (this.$refs.serialSigner.isAuthenticated()) {
          if (wallet.meta?.accountPath) {
            const branchIndex = addressData.isChange ? 1 : 0
            const path =
              wallet.meta.accountPath +
              `/${branchIndex}/${addressData.addressIndex}`
            this.$refs.serialSigner.hwwShowAddress(path, addressData.address)
          }
        } else {
          this.$q.notify({
            type: 'warning',
            message: 'Please login in order to confirm address on device',
            timeout: 10000
          })
        }
      }
    },
    initUtxos: function (addresses) {
      if (!this.fetchedUtxos && addresses.length) {
        this.fetchedUtxos = true
        this.addresses = addresses
        // this.scanAddressWithAmount()
      }
    },
    handleBroadcastSuccess: async function (txId) {
      this.tab = 'history'
      this.searchInTab({tab: 'history', value: txId})
      this.showPayment = false
      // await this.refreshAddresses()
      // await this.scanAddressWithAmount()
    },    
  },
  created: async function () {       
  }
})
