<script>
	import { createEventDispatcher, tick } from "svelte";
	import { fade } from "svelte/transition";
  export let config = {};
  export let name;
	export let style = '';
	export let value;

	let err = '';

  const dispatch = createEventDispatcher();

  async function handleInput() {
	  await tick();
	  dispatch('input', true);
  }

	async function handleBlur() {
		validate();
		dispatch('blur', true);
  }

	export function validate() {
    err = '';

		if (!config.validation?.required && !value) {
			return true;
    }

		if (config.validation?.required && !value) {
			err = 'Required';
			return false;
    }

		if (config.validation?.regex && !value.match(config.validation.regex)) {
			err = config.validation.errMsg || 'Invalid input';
			return false;
		}

		return true;
  }

</script>

<div class="inputRow" transition:fade|global="{{ duration: 200 }}">
  <input
      type="text"
      name={name}
      class={err ? config.inputErrClass || 'inputErr' : config.inputOkClass || 'input'}
      style={style}
      bind:value={value}
      placeholder={config.placeholder}
      on:input={handleInput}
      on:blur={handleBlur}
  />
</div>

{#if err}
  <div class={config.errMsgClass || 'err'}>
    {err}
  </div>
{/if}

<style>
    .err {
        margin-top: -5px;
        margin-bottom: 5px;
        padding-left: 7px;
        color: var(--col-err);
    }

    .inputRow {
        display: flex;
        align-items: center;
    }
</style>
