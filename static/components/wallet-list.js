window.app.component('wallet-list', {
  name: 'wallet-list',
  template: '#wallet-list',
  delimiters: ['${', '}'],

  props: [
    'adminkey',
    'inkey',
    'sats-denominated',
    'addresses',
    'network'    
  ],
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
      showCreating: false,
      showUpdating: false,
      walletsTable: {
        columns: [          
          {name: 'id', align: 'left', label: 'ID', field: 'id'},                  
          {
            name: 'title',
            align: 'left',
            label: 'Title',
            field: 'title'
          },                    
          {
            name: 'hr_address',
            align: 'left',
            label: 'HR Address',
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

  methods: {
    satBtc(val, showUnit = true) {
      return satOrBtc(val, showUnit, this.satsDenominated)
    },        
    addWalletAccount: async function () {
      this.showCreating = true
      const data = _.omit(this.formDialog.data, 'wallet')
      data.network = this.network      
      data.mnemonic = CryptoJS.AES.encrypt(data.mnemonic, data.last_height).toString();            
      await this.createWalletAccount(data)      
      this.showCreating = false
    },
    updateWalletAccount: async function () {
      this.showUpdating = true
      const data = _.omit(this.updateDialog.data, 'wallet')
      data.network = this.network           
      if (data.id) {
        await this.updateHRAddressHeight(data)
      }      
      this.showUpdating = false
    },
    createWalletAccount: async function (data) {
      try { 
        console.log(data)     
        const response = await LNbits.api.request(
          'POST',
          '/silnt/api/v1/wallet',
          this.adminkey,
          data
        )        
        this.walletAccounts.push(mapWalletAccount(response.data))
        this.formDialog.show = false

        await this.refreshWalletAccounts()
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }      
          Quasar.Notify.create({
            type: 'positive',
            message: 'Silent Payment Wallet Added.'
      })
    },
    updateWalletDialog(walletAccountId) {
      var wallet = _.findWhere(this.walletAccounts, {id: walletAccountId})
      this.updateDialog.data = _.clone(wallet)      
      this.updateDialog.hr_address = this.updateDialog.data.hr_address
      this.updateDialog.last_height = this.updateDialog.data.last_height
      this.updateDialog.show = true
    },
    updateHRAddressHeight: async function (data) {      
      try {        
        const response = await LNbits.api.request(
          'POST',
          '/silnt/api/v1/wallet' + data.id,
          this.adminkey,
          data
        )            
        this.walletAccounts.push(mapWalletAccount(response.data))
        this.updateDialog.show = false

        await this.refreshWalletAccounts()
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }      
          Quasar.Notify.create({
            type: 'positive',
            message: 'Wallet updated.'
      })
    },
    deleteWalletDialog: function (walletAccountId) {
      LNbits.utils
        .confirmDialog(
          'Are you sure you want to delete this Silnt wallet?'
        )
        .onOk(async () => {
          try {
            await LNbits.api.request(
              'DELETE',
              '/silnt/api/v1/wallet/' + walletAccountId,
              this.adminkey
            )
            this.walletAccounts = _.reject(this.walletAccounts, function (obj) {
              return obj.id === walletAccountId
            })
            await this.refreshWalletAccounts()
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
    getSilntWallets: async function () {
      try {
        const {data} = await LNbits.api.request(
          'GET',
          `/silnt/api/v1/wallet`,
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
      const wallets = await this.getSilntWallets()      
      this.walletAccounts = wallets.map(w => mapWalletAccount(w))      
      // this.$emit('accounts-update', this.walletAccounts)
    },
    // getBalanceForWallet: function (walletId) {
    //   const amount = this.addresses
    //     .filter(a => a.wallet === walletId)
    //     .reduce((t, a) => t + a.amount || 0, 0)
    //   return this.satBtc(amount)
    // },
    closeFormDialog: function () {
      this.formDialog.data = {
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
    openGetFreshAddressDialog: async function (walletId) {
      const {data} = await LNbits.api.request(
        'GET',
        `/silnt/api/v1/address/${walletId}`,
        this.inkey
      )
      const addressData = mapAddressesData(data)

      addressData.note = `Shared on ${currentDateTime()}`
      const lastActiveAddress =
        this.addresses
          .filter(
            a => a.wallet === addressData.wallet && !a.isChange && a.hasActivity
          )
          .pop() || {}
      addressData.gapLimitExceeded =
        !addressData.isChange &&
        addressData.addressIndex >
          lastActiveAddress.addressIndex + DEFAULT_RECEIVE_GAP_LIMIT

      const wallet = this.walletAccounts.find(w => w.id === walletId) || {}
      wallet.address_no = addressData.addressIndex
      this.$emit('new-receive-address', {addressData, wallet})
    },
    showAddAccountDialog: function () {
      this.formDialog.show = true      
    },
    showUpdateWalletDialog: function () {
      this.updateDialog.show = true      
    },
    // todo: bad. base.js not present in custom components
    copyText: function (text, message, position) {
      var notify = this.$q.notify
      Quasar.utils.copyToClipboard(text).then(function () {
        notify({
          message: message || 'Copied to clipboard!',
          position: position || 'bottom'
        })
      })
    },    
  },
  created: async function () {   
    if (this.inkey) {
      await this.refreshWalletAccounts()          
    }
  }
})
