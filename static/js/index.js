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
      showBip353Dialog: false,
      bip353Address: '',
      bip353Result: '',
      bip353Loading: false,
      qrCodeDialog: {
        show: false,
        data: null
      },
      ...tables,
      ...tableData,
      walletAccounts: [],            
      utxosFilter: '',
      network: null,
      lastScanResult: null,
      showSendDialog: false,
      sendWallet: null,
      sendUtxos: [],
      sendForm: {
        recipient: '',
        amount: 0,
        feeRate: 1,
        memo: '',
        useAllUtxos: false
      },
      sendLoading: false,
      broadcastLoading: false,
      sendTxResult: null,     
    }
  },
  computed: {
    sendSelectedTotal: function () {
        return this.sendUtxos
    .filter(u => u.selected)
    .reduce((sum, u) => sum + (u.amount || 0), 0)
  },
    canBuildTx: function () {
      const hasRecipient = !!this.sendForm.recipient
      const hasUtxos = this.sendUtxos.some(u => u.selected) || this.sendForm.useAllUtxos
      const hasAmount = this.sendForm.useAllUtxos || this.sendForm.amount > 0
      const hasFee = this.sendForm.feeRate > 0
      return hasRecipient && hasUtxos && hasAmount && hasFee && !this.sendLoading
    },
    mempoolHostname: function () {      
      if (!this.config || !this.config.isLoaded) return 'mempool.space'
      try {
        const endpoint = this.config.mempool_endpoint || 'https://mempool.space'
        let hostname = new URL(endpoint).hostname
        if ((this.config.network || '').toLowerCase() === 'testnet') {
          hostname += '/testnet'
        }
        return hostname
      } catch (e) {
        return 'mempool.space'
      }
    },    
  },

  methods: {

    //################### UTXOs ###################
    scanSilentPayAddress: async function (wallet) {
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
          vout: u.vout || 0,          
          utxo_state: u.utxo_state,
          label: u.label,
          timestamp: u.timestamp,
          wallet: wallet?.id,
          priv_key_tweak: u.priv_key_tweak || '',
          pub_key: u.pub_key || ''
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
    resolveBip353: async function () {
      if (!this.bip353Address) return
      this.bip353Loading = true
      this.bip353Result = ''
      try {
        const {data} = await LNbits.api.request(
          'GET',
          `/silnt/api/v1/bip353/resolve?address=${encodeURIComponent(this.bip353Address)}`,
          this.g.user.wallets[0].inkey
        )

        // Strip bitcoin:?sp= / bitcoin:?lno= / lno= prefixes
        let result = data.result || ''        
        result = result.replace(/^bitcoin:\?sp=/i, '')
        result = result.replace(/^bitcoin:\?lno=/i, '')
        result = result.replace(/^lno=/i, '')
        result = result.replace(/^sp=/i, '')
        this.bip353Result = result.trim()        
        this.$q.notify({
          type: 'positive',
          message: `BIP353 resolved for ${this.bip353Address}`,
          timeout: 5000
        })
      } catch (err) {
        LNbits.utils.notifyApiError(err)
      } finally {
        this.bip353Loading = false
      }
    },
    copyText: function (text) {
      Quasar.copyToClipboard(text).then(() => {
        this.$q.notify({
          message: 'Copied to clipboard!',
          position: 'bottom'
        })
      })
    },        
    clearUtxosForWallet: function (walletId) {
      // Check if any displayed UTXOs belong to the deleted wallet
      const hasUtxos = this.utxos.data.some(u => u.wallet === walletId)
      if (!hasUtxos) return

      // Clear UTXOs and reset totals
      this.utxos.data = []
      this.utxos.total = 0
      this.lastScanResult = null

      this.$q.notify({
        type: 'info',
        message: 'UTXOs cleared for deleted wallet.',
        timeout: 5000
      })
    }, 
    openSendDialog: function (wallet) {
      this.sendWallet = wallet
      this.sendTxResult = null
      this.sendForm = {
        recipient: '',
        amount: 0,
        feeRate: 1,
        memo: '',
        useAllUtxos: false
      }
      // Load unspent UTXOs for this wallet
      this.sendUtxos = (this.utxos.data || [])
        .filter(u => u.utxo_state === 'unspent' && u.wallet === wallet.id)
        .map(u => ({ ...u, selected: false }))
      this.showSendDialog = true
    },

    onUseAllUtxos: function (val) {
      if (val) {
        this.sendUtxos.forEach(u => { u.selected = true })
        this.sendForm.amount = this.sendSelectedTotal
      } else {
        this.sendUtxos.forEach(u => { u.selected = false })
        this.sendForm.amount = 0
      }
    },
    buildTransaction: async function () {
      this.sendLoading = true
      this.sendTxResult = null
      try {
        const selectedUtxos = this.sendUtxos.filter(u => u.selected)       
        const {data} = await LNbits.api.request(
          'POST',
          '/silnt/api/v1/tx/build',
          this.g.user.wallets[0].adminkey,
          {
            wallet_id: this.sendWallet.id,
            recipient: this.sendForm.recipient,
            amount: this.sendForm.useAllUtxos ? this.sendSelectedTotal : this.sendForm.amount,
            fee_rate: this.sendForm.feeRate,
            memo: this.sendForm.memo,
            utxos: selectedUtxos.map(u => ({
              txid: u.txid,
              amount: u.amount,
              label: u.label,
              vout: u.vout || 0,
              priv_key_tweak: u.priv_key_tweak,
              pub_key: u.pub_key
            }))
          }
        )        
        this.sendTxResult = data.psbt || data.tx_hex || JSON.stringify(data)
        this.$q.notify({
          type: 'positive',
          message: 'Transaction built successfully.',
          timeout: 5000
        })
      } catch (err) {
        LNbits.utils.notifyApiError(err)
      } finally {
        this.sendLoading = false
      }
    },
    broadcastTransaction: async function () {
      this.broadcastLoading = true
      try {
        await LNbits.api.request(
          'POST',
          '/silnt/api/v1/tx/broadcast',
          this.g.user.wallets[0].adminkey,
          { tx_hex: this.sendTxResult }
        )
        this.$q.notify({
          type: 'positive',
          message: 'Transaction broadcast successfully!',
          timeout: 8000
        })
        this.showSendDialog = false
        this.sendTxResult = null
      } catch (err) {
        LNbits.utils.notifyApiError(err)
      } finally {
        this.broadcastLoading = false
      }
    },

    copyText: function (text) {
      Quasar.copyToClipboard(text).then(() => {
        this.$q.notify({
          message: 'Copied to clipboard!',
          position: 'bottom'
        })
      })
    },               
  },
  created: async function () {       
  }
})
