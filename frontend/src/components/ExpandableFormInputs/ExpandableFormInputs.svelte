<script>
  import { getKey } from "../../utils/helpers.js";
  import DynamicInputRow from "./DynamicInputRow.svelte";
  import { createEventDispatcher, onMount } from "svelte";

	// global config for each of the inputs
  export let config = {
    inputErrClass: '',
    inputOkClass: '',
    errMsgClass: '',
    placeholder: 'default',
    validation: {
			required: false,
      regex: undefined,
      errMsg: '',
    },
  };

	// this style will be added to the <input>'s
	export let style = '';

	// the inputs with a name and value - can be left empty, if no initial values are present
  // IMPORTANT: Do not provide the 'validate' function field!
	export let inputs = [{
		name: getKey(),
    value: '',
  }];

  const dispatch = createEventDispatcher();

	// adds an empty row at the end, if the given values already have a valid input
	onMount(() => {
		if (inputs.length > 0 && inputs[0].value) {
			inputs.push({
				name: getKey(),
				value: '',
			});
    }
  })

  function handleInput() {
		if (inputs[inputs.length - 1].value) {
			inputs.push({
        name: getKey(),
        value: '',
      });
    } else if (inputs.length > 1 && !inputs[inputs.length - 2].value) {
			inputs = [...inputs.slice(0, inputs.length - 1)];
    }

	  dispatch('input', true);
  }

  // can be called to validate every input and returns true, if everything is ok
  export function validate() {
		for (let i of inputs) {
			if (i.value && !i.validate()) {
				return false;
      }
    }

    return true;
  }
</script>

<div>
  {#each inputs as input}
    <DynamicInputRow
        config={config}
        bind:name={input.name}
        bind:value={input.value}
        bind:validate={input.validate}
        on:input={handleInput}
        on:blur={handleInput}
        bind:style
    />
  {/each}
</div>
