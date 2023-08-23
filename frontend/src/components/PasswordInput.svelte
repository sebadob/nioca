<script>
	import IconEye from "./icons/IconEye.svelte";
	import IconEyeSlash from "./icons/IconEyeSlash.svelte";
	import { createEventDispatcher } from "svelte";
	import IconClipboard from "./icons/IconClipboard.svelte";

	export let name = '';
	export let placeholder = '';
    export let disabled = false;
	export let showClip = true;
	export let value = '';
	export let width = 320;
    export let newPassword = false;

	let hoverCopy = false;
    let type = newPassword ? 'new-password' : 'password';

	const dispatch = createEventDispatcher();

	function copyToClip() {
    navigator.clipboard.writeText(value);
  }

	function handleKeyPress() {
		dispatch('keypress', true);
	}

	function handleOnBlur() {
		dispatch('blur', true);
	}

	function toggle() {
		if (type === 'password') {
			type = 'text';
		} else {
			type = 'password';
		}
	}

	function onInput(event) {
		value = event.target.value
	}

</script>

<div class="container">
  <div>
    <input
        class="input font-mono"
        style:width={`${width}px`}
        {type}
        {name}
        {value}
        {placeholder}
        {disabled}
        {...$$restProps}
        on:input={onInput}
        on:keypress={handleKeyPress}
        on:blur={handleOnBlur}
    />
  </div>

  <div class="iconWrapper">
    <div
        class="copy"
        on:mouseenter={() => hoverCopy = true}
        on:mouseleave={() => hoverCopy = false}
        on:click={copyToClip}
        on:keypress={copyToClip}
    >
      {#if value && showClip}
        <IconClipboard color={hoverCopy ? 'var(--col-ok)' : 'var(--col-text)'} />
      {/if}
    </div>
  </div>

  <div class="iconWrapper">
    <div class="show" on:click={toggle} on:keypress={toggle}>
      {#if type === 'password'}
        <IconEyeSlash width={22} />
      {:else}
        <IconEye width={22} />
      {/if}
    </div>
  </div>
</div>

<style>
    .container {
      display: flex;
      justify-content: center;
      align-items: center;
    }

    .input {
        padding-right: 50px;
    }

    .iconWrapper {
        position: relative;
    }

    .copy {
        position: absolute;
        top: -11px;
        right: 33px;
        opacity: 0.85;
        cursor: pointer;
    }

    .show {
        position: absolute;
        top: -11px;
        right: 8px;
        opacity: 0.85;
        cursor: pointer;
    }
</style>
