import FormExtension from '@ohos.app.form.FormExtensionAbility';
import formBindingData from '@ohos.app.form.formBindingData';
import Want from '@ohos.app.ability.Want';

/** Minimal form provider owned by this smoke-test HAP. */
export default class VfSmokeFormExtension extends FormExtension {
  onAddForm(_want: Want): formBindingData.FormBindingData {
    return formBindingData.createFormBindingData({ label: 'VulnFounder smoke form' });
  }

  onRemoveForm(_formId: string): void {
    // The provider owns no external resources; this callback is intentionally empty.
  }
}
