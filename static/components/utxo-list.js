window.app.component('utxo-list', {
  name: 'utxo-list',
  template: '#utxo-list',
  delimiters: ['${', '}'],

  props: [
    'utxos',
    'accounts',
    'selectable',
    'payed-amount',
    'sats-denominated',
    'mempool-endpoint',
    'filter'
  ],

  data: function () {
    return {
      utxosTable: {
        columns: [
          {
            name: 'expand',
            align: 'left',
            label: ''
          },
          {
            name: 'selected',
            align: 'left',
            label: '',
            selectable: true
          },
          {
            name: 'status',
            align: 'center',
            label: 'Status',
            field: 'utxo_state',
            sortable: true
          },
          {
            name: 'amount',
            align: 'left',
            label: 'Amount',
            field: 'amount',
            sortable: true
          },
          {
            name: 'date',
            align: 'left',
            label: 'Date',
            field: 'timestamp',
            sortable: true,
            sort: (a, b) => a - b
          }
        ],
        pagination: {
          rowsPerPage: 10
        }
      },
      utxoSelectionModes: [
        'Manual',
        'Random',
        'Select All',
        'Smaller Inputs First',
        'Larger Inputs First'
      ],
      utxoSelectionMode: 'Random',
      utxoSelectAmount: 0
    }
  },

  computed: {
    columns: function () {
      return this.utxosTable.columns.filter(c =>
        c.selectable ? this.selectable : true
      )
    },
    unspentTotal: function () {
      return (this.utxos || [])
        .filter(u => u.utxo_state === 'unspent')
        .reduce((t, u) => t + (u.amount || 0), 0)
    },
    spentTotal: function () {
      return (this.utxos || [])
        .filter(u => u.utxo_state === 'spent')
        .reduce((t, u) => t + (u.amount || 0), 0)
    }
  },

  methods: {
    satBtc(val, showUnit = true) {
      return satOrBtc(val, showUnit, this.satsDenominated)
    },
    // Kept for compatibility but not used for blindbit UTXOs (no wallet account)
    getWalletName: function (walletId) {
      const wallet = (this.accounts || []).find(wl => wl.id === walletId)
      return wallet ? wallet.title : 'unknown'
    },
    getTotalSelectedUtxoAmount: function () {
      const total = (this.utxos || [])
        .filter(u => u.selected)
        .reduce((t, a) => t + (a.amount || 0), 0)
      return total
    },
    refreshUtxoSelection: function (totalPayedAmount) {
      this.utxoSelectAmount = totalPayedAmount
      this.applyUtxoSelectionMode()
    },
    updateUtxoSelection: function () {
      this.utxoSelectAmount = this.payedAmount
      this.applyUtxoSelectionMode()
    },
    applyUtxoSelectionMode: function () {
      const mode = this.utxoSelectionMode
      const isSelectAll = mode === 'Select All'
      if (isSelectAll) {
        this.utxos.forEach(u => (u.selected = true))
        return
      }

      const isManual = mode === 'Manual'
      if (isManual || !this.utxoSelectAmount) return

      this.utxos.forEach(u => (u.selected = false))

      const isSmallerFirst = mode === 'Smaller Inputs First'
      const isLargerFirst = mode === 'Larger Inputs First'
      let selectedUtxos = this.utxos.slice()
      if (isSmallerFirst || isLargerFirst) {
        const sortFn = isSmallerFirst
          ? (a, b) => a.amount - b.amount
          : (a, b) => b.amount - a.amount
        selectedUtxos.sort(sortFn)
      } else {
        // default to random order
        selectedUtxos = _.shuffle(selectedUtxos)
      }
      selectedUtxos.reduce((total, utxo) => {
        utxo.selected = total < this.utxoSelectAmount
        total += utxo.amount
        return total
      }, 0)
    }
  },

  created: async function () {}
})