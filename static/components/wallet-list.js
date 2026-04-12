window.app.component('wallet-list', {
  name: 'wallet-list',
  template: '#wallet-list',
  delimiters: ['${', '}'],

  props: [
    'adminkey',
    'inkey',
    'sats-denominated',
    // 'addresses',
    'network',
    'scannedUtxos'   
  ],
  emits: ['accounts-update',  'fetch-utxos', 'scan-wallet', 'clear-utxos', 'open-bip353', 'send-wallet'],
  data: function () {
    return {
      walletAccounts: [],
      address: {},      
      formDialog: {
        show: false,                
        data: {
          title: '',          
          hr_address: '',
          last_height: ''          
        }
      },
      updateDialog: {
        show: false,                
        data: {
          title: '',          
          hr_address: '',
          last_height: ''          
        }
      },
      qrDialog: {
        show: false,
        address: ''
      },
      bip353Valid: true,          
      showCreating: false,
      showUpdating: false,
      walletsTable: {
        columns: [          
          {name: 'sp_address', align: 'left', label: 'SP Address', field: 'sp_address'},                  
          {
            name: 'title',
            align: 'left',
            label: 'Title',
            field: 'title'
          },                    
          {
            name: 'hr_address',
            align: 'left',
            label: 'BIP353 Address',
            field: 'hr_address'
          },
          {
            name: 'last_height',
            align: 'left',
            label: 'Height',
            field: 'last_height'
          },
          {
            name: 'balance',
            align: 'left',
            label: 'Balance',
            field: 'balance'
          }       
        ],
        pagination: {
          rowsPerPage: 10
        }
      }      
    }
  },  
  watch: {
  scannedUtxos: {
    deep: true,
    handler(result) {      
      if (!result || !result.utxos || !result.utxos.length) return

      const newBalance = result.utxos
          .filter(u => u.utxo_state === 'unspent')         
          .reduce((sum, u) => sum + (u.amount || 0), 0)      
      this.walletAccounts.forEach(async wallet => {        
        // Only update if balance actually changed
        if (newBalance === wallet.balance) return

        // Update backend first
        await this.updateWalletBalance(wallet.id, newBalance)

        // Then update local state reactively
        wallet.balance = newBalance
      })
    }
  }
},
  methods: {
    satBtc(val, showUnit = true) {
      return satOrBtc(val, showUnit, this.satsDenominated)
    },        
    addWalletAccount: async function () {
      this.showCreating = true
      const data = _.omit(this.formDialog.data, 'wallet')
      data.network = this.network
      // Validate BIP353 hr_address if provided
      if (data.hr_address && data.hr_address.trim() !== '') {
        const valid = await this.validateBip353(data.hr_address)
        if (!valid) {
          this.showCreating = false
          return
        }
      }     
      data.mnemonic = CryptoJS.AES.encrypt(data.mnemonic, data.last_height).toString();            
      await this.createWalletAccount(data)      
      this.showCreating = false
    },
    updateWalletAccount: async function () {
      this.showUpdating = true
      const data = _.omit(this.updateDialog.data, 'wallet')
      data.network = this.network
      // Validate BIP353 hr_address if provided
      if (data.hr_address) {
        const valid = await this.validateBip353(data.hr_address)
        if (!valid) {
          this.showUpdating = false
          return
        }
      }          
      if (data.id) {
        await this.updateWalletDetails(data)
      }      
      this.showUpdating = false
    },
    createWalletAccount: async function (data) {
      try {             
        const response = await LNbits.api.request(
          'POST',
          '/siLNt/api/v1/wallet',
          this.inkey,
          data
        )        
        this.walletAccounts.push(mapWalletAccount(response.data))
        this.formDialog.show = false

        await this.refreshWalletAccounts()
        Quasar.Notify.create({
            type: 'positive',
            message: 'Silent Payment Wallet Added.'
      })
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }                
    },
    updateWalletDialog(walletAccountId) {
      var wallet = _.findWhere(this.walletAccounts, {id: walletAccountId})
      this.updateDialog.data = _.clone(wallet)      
      this.updateDialog.hr_address = this.updateDialog.data.hr_address
      this.updateDialog.last_height = this.updateDialog.data.last_height
      this.updateDialog.title = this.updateDialog.data.title
      this.updateDialog.show = true
      this.bip353Valid = true
    },
    updateWalletDetails: async function (data) {      
      try {        
        const response = await LNbits.api.request(
          'PUT',
          '/siLNt/api/v1/wallet/' + data.id,
          this.inkey,
          data
        )            
        this.walletAccounts.push(mapWalletAccount(response.data))
        this.updateDialog.show = false
        await this.refreshWalletAccounts()
        Quasar.Notify.create({
            type: 'positive',
            message: 'Wallet updated.'
      })
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }                
    },
    deleteWalletDialog: function (walletAccountId) {
      LNbits.utils
        .confirmDialog(
          'Are you sure you want to delete this wallet?'
        )
        .onOk(async () => {
          try {
            await LNbits.api.request(
              'DELETE',
              '/siLNt/api/v1/wallet/' + walletAccountId,
              this.inkey
            )
            this.walletAccounts = _.reject(this.walletAccounts, function (obj) {
              return obj.id === walletAccountId
            })
            await this.refreshWalletAccounts()
            this.$emit('clear-utxos',walletAccountId)
          } catch (error) {
            this.$q.notify({
              type: 'warning',
              message: 'Error while deleting wallet account. Please try again.',
              timeout: 10000
            })
          }
        })
    },
// ?network=${this.network}
    getsiLNtWallets: async function () {      
      try {
        const {data} = await LNbits.api.request(
          'GET',
          `/siLNt/api/v1/wallet`,
          this.inkey
        )        
        return data
      } catch (error) {        
        this.$q.notify({
          type: 'warning',
          message: 'Failed to fetch wallets.',
          timeout: 10000
        })
        LNbits.utils.notifyApiError(error)
      }
      return []
    },
    refreshWalletAccounts: async function () {
      this.walletAccounts = []
      const wallets = await this.getsiLNtWallets()           
      this.walletAccounts = wallets.map(w => mapWalletAccount(w))      
      this.$emit('accounts-update', this.walletAccounts)
    },
    updateWalletBalance: async function (walletId, balance) {
      try {        
        await LNbits.api.request(
          'PUT',
          `/siLNt/api/v1/wallet/${walletId}`,
          this.inkey,
          { balance }
        )
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }
    },
    validateBip353: async function (address) {
      // Basic email format check first
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      if (!emailRegex.test(address)) {
        this.$q.notify({
          type: 'warning',
          message: 'BIP353 Address must be in email format (e.g. alice@domain.com)',
          timeout: 8000
        })
        // this.bip353Valid = false
        return false
      }
      try {
        await LNbits.api.request(
          'GET',
          `/siLNt/api/v1/bip353/resolve?address=${encodeURIComponent(address)}`,
          this.inkey
        )
        this.$q.notify({
          type: 'positive',
          message: `BIP353 address verified: ${address}`,
          timeout: 5000
        })
        this.bip353Valid = true
        return true
      } catch (error) {
        this.$q.notify({
          type: 'negative',
          message: `BIP353 resolution failed for ${address} — check the address and try again`,
          timeout: 8000
        })
        // this.bip353Valid = false
        return false
      }
    },
    // getBalanceForWallet: function (walletId) {
    //   const amount = this.addresses
    //     .filter(a => a.wallet === walletId)
    //     .reduce((t, a) => t + a.amount || 0, 0)
    //   return this.satBtc(amount)
    // },
    closeFormDialog: function () {
      this.formDialog.data = {               
        hr_address: '',     // ← empty string not null
        last_height: '',
        mnemonic: '',     
        is_unique: false
      }
    },
    closeUpdateDialog: function () {
      this.updateDialog.data = {
        is_unique: false
      }
    },
    getAccountDescription: function (accountType) {
      return getAccountDescription(accountType)
    },
    
    showAddAccountDialog: function () {
      this.formDialog.data = {      
      hr_address: '',
      last_height: '',
      mnemonic: ''
    }
      this.formDialog.show = true      
    },
    showUpdateWalletDialog: function () {
      this.updateDialog.show = true      
    },
    // todo: bad. base.js not present in custom components
    copyText: function (text, message, position) {
      var notify = this.$q.notify
      Quasar.copyToClipboard(text).then(function () {
        notify({
          message: message || 'Copied to clipboard!',
          position: position || 'bottom'
        })
      })
    },
    showQrCode: function (wallet) {
      this.qrDialog.address = wallet.sp_address || ''
      this.qrDialog.show = true
    },    
  },
  created: async function () {   
    if (this.inkey) {
      await this.refreshWalletAccounts()          
    }
  }
})
