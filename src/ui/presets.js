import { invoke } from '@tauri-apps/api/core'
import { t } from '../i18n.js'
import { app, onChange, applyProfileSnapshot } from '../main.js'
import { openModal, modalButton, confirmModal } from './modal.js'
import { icon } from './icons.js'
import { toast } from './toast.js'
export const presetLabel = p => p?.id === 'default' && p.name === 'Default' ? t('Default') : p?.name || t('Default')
export function createPresetSelector() {
  let data = { activeId:'default', presets:[{id:'default',name:'Default'}] }
  const root=document.createElement('div');root.className='presets'
  const trigger=document.createElement('button');trigger.className='btn presets__trigger';trigger.type='button'
  trigger.setAttribute('aria-haspopup','dialog');root.append(trigger)
  const paint=()=>{trigger.textContent=presetLabel(data.presets.find(p=>p.id===data.activeId));trigger.disabled=!app.profile || !['DISCONNECTED','FAILED'].includes((app.snapshot?.state||"DISCONNECTED"))}
  const refresh=async()=>{try {const state=await invoke('preset_state');if(state?.presets?.length)data=state;paint()}catch{paint()}}
  const action=async(action,id=null,name=null)=>{try {
    data=await invoke('preset_action',{action,id,name});
    const profile=await invoke('get_profile');if(profile)applyProfileSnapshot(profile);paint()
  }catch(error){toast(String(error))}}
  const naming=(preset=null)=>{
    const m=openModal({title:t(preset?'Rename profile':'Save current settings as a new profile'),onEscape:()=>m.close()})
    const input=document.createElement('input');input.className='input';input.maxLength=40;input.value=preset?.name||'';input.setAttribute('aria-label',t('Name'));m.body.append(input)
    const save=()=>{if(input.value.trim()){m.close();action(preset?'rename':'save',preset?.id,input.value.trim())}}
    input.onkeydown=e=>{if(e.key==='Enter'){e.preventDefault();save()}}
    m.actions.append(modalButton(t('Cancel'),'btn--ghost',()=>m.close()),modalButton(t('Save'),'btn--primary',save));input.focus()
  }
  const iconSpan=name=>{const e=document.createElement('span');e.className='presets__actionicon';e.innerHTML=icon(name,20);return e}
  const fileInput=document.createElement('input');fileInput.type='file';fileInput.accept='.json,application/json,text/plain';fileInput.hidden=true;root.append(fileInput)
  fileInput.onchange=async()=>{
    const file=fileInput.files?.[0];if(!file)return
    try{
      if(file.size>256*1024)throw new Error(t('Import is too large'))
      data=await invoke('preset_import',{text:await file.text()})
      const applied=data?.applied===true
      if(applied){const profile=await invoke('get_profile');if(profile)applyProfileSnapshot(profile)}
      paint();toast(t(applied?'Profile imported and applied.':'Profiles imported. Select one to apply it.'))
    }catch(error){toast(t(String(error?.message||error)))}
    fileInput.value=''
  }
  const exportSelected=async()=>{
    try{
      // Native "Save as" dialog; `null` means the user cancelled (nothing is written).
      const saved=await invoke('preset_export_save')
      if(saved)toast(t('Profile exported without secrets.'))
    }catch(error){toast(t(String(error?.message||error)))}
  }
  trigger.onclick=()=>{
    const m=openModal({title:t('Connection profiles'),onEscape:()=>m.close()})
    const list=document.createElement('div');list.className='presets__list'
    for(const preset of data.presets){
      const row=document.createElement('div');row.className='presets__row'
      const pick=document.createElement('button');pick.type='button';pick.className='presets__pick'
      const mark=document.createElement('span');mark.innerHTML=icon(preset.id===data.activeId?'check':'tune',20)
      const name=document.createElement('span');name.className='presets__name';name.textContent=presetLabel(preset);name.title=name.textContent
      pick.append(mark,name);pick.onclick=()=>{m.close();action('select',preset.id)}
      row.append(pick)
      // The built-in "default" profile is locked: no rename and no delete controls at all.
      if(preset.id!=='default'){
        const rename=document.createElement('button');rename.type='button';rename.className='presets__icon';rename.innerHTML=icon('edit',18);rename.setAttribute('aria-label',t('Rename profile'));rename.onclick=()=>{m.close();naming(preset)}
        const del=document.createElement('button');del.type='button';del.className='presets__icon presets__icon--danger';del.innerHTML=icon('delete',18);del.setAttribute('aria-label',t('Delete profile'));del.onclick=async()=>{m.close();if(await confirmModal({title:t('Delete profile'),body:presetLabel(preset),ok:t('Delete'),cancel:t('Cancel'),danger:true}))action('delete',preset.id)}
        row.append(rename,del)
      }
      list.append(row)
    }
    const divider=document.createElement('hr');divider.className='presets__divider'
    const save=modalButton(t('Save current settings as a new profile'),'presets__save',()=>{m.close();naming()});save.prepend(document.createTextNode('+ '))
    const imp=modalButton(t('Import settings'),'presets__save presets__action',()=>{fileInput.value='';fileInput.click()});imp.prepend(iconSpan('file_download'))
    const exp=modalButton(t('Export selected profile (non-secret)'),'presets__save presets__action',()=>{m.close();exportSelected()});exp.prepend(iconSpan('file_upload'))
    m.body.append(list,divider,save,imp,exp);m.actions.append(modalButton(t('Cancel'),'btn--ghost',()=>m.close()))
  }
  onChange(paint,root);paint();refresh();return root
}
