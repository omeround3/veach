<template>
  <div class="row card mx-1" :class="directionReverse ? reverseDirection : ''">
    <div class="col-10 card-header p-3 pt-2">
      <div class="row">
        <div class="col-9 pt-1" :class="isRTL ? 'text-end' : 'text-start'">
          <p class="text-sm mb-0 text-capitalize">{{ title.text }}</p>
          <h4 class="mb-0">{{ title.value }}</h4>
        </div>
        <div class="col-3">
          <button v-if="title.text == 'Total CVE Records In DB'" type="button" class="btn btn-veach-red"
            style="font-size: 10px" @click="scan">
            UPDATE
          </button>
        </div>
      </div>
    </div>

    <hr class="dark horizontal my-0" />
    <div class="card-footer p-3" :class="isRTL ? 'text-end' : 'text-start'">
      <!--  eslint-disable-next-line vue/no-v-html -->
      <p class="mb-0" v-html="detail"></p>
    </div>
  </div>
</template>

<script>
import { mapState } from "vuex";
export default {
  name: "MiniStatisticsCard",
  data() {
    return {
      reverseDirection: "flex-row-reverse justify-content-between",
    };
  },
  props: {
    title: {
      type: Object,
      required: true,
      text: String,
      value: [Number, String],
    },
    detail: {
      type: String,
      default: "",
    },
    directionReverse: {
      type: Boolean,
      default: false,
    },
  },
  computed: {
    ...mapState(["isRTL"]),
  },
};
</script>
