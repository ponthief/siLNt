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
      lastScanResult: null      
    }
  },
  computed: {    
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
          utxo_state: u.utxo_state,
          label: u.label,
          timestamp: u.timestamp,
          wallet: wallet?.id
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
  },
  created: async function () {       
  }
})
