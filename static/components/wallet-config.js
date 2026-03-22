window.app.component('wallet-config', {
  name: 'wallet-config',
  template: '#wallet-config',
  delimiters: ['${', '}'],

  props: ['total', 'config-data', 'adminkey'],
  emits: ['update:config-data'],
  data: function () {
    return {
      networkOptions: ['mainnet', 'testnet'],
      internalConfig: {},
      show: false
    }
  },

  computed: {
    config: {
      get() {
        return this.internalConfig
      },
      set(value) {
        value.isLoaded = true
        // Ensure blindbit auth fields are always present
        value.blindbit_url = value.blindbit_url || ''
        value.blindbit_user = value.blindbit_user || ''
        value.blindbit_pass = value.blindbit_pass || ''
        this.internalConfig = JSON.parse(JSON.stringify(value))
        this.$emit(
          'update:config-data',
          JSON.parse(JSON.stringify(this.internalConfig))
        )
      }
    }
  },

  methods: {    
    updateConfig: async function () {
      try {
        const {data} = await LNbits.api.request(
          'PUT',
          '/silnt/api/v1/blindbit/config',
          this.adminkey,
          this.config
        )
        this.show = false
        this.config = data
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }
    },
    getConfig: async function () {
      try {
        const {data} = await LNbits.api.request(
          'GET',
          '/silnt/api/v1/blindbit/config',
          this.adminkey
        )
        this.config = data
      } catch (error) {
        LNbits.utils.notifyApiError(error)
      }
    }
  },
  created: async function () {
    await this.getConfig()
  }
})