"use client";

export default function CreateQuestion() {
  return (
    <div className="w-full max-w-4xl mx-auto mt-10">
      <div className="space-y-4 bg-gray-800 p-8 rounded-lg w-full mx-auto border border-gray-700">
        <h2 className="text-lg font-bold text-center text-white">
          Ajoutez Votre Question
        </h2>
      </div>
      <div className="space-y-4 bg-gray-800 p-8 rounded-lg w-full mx-auto mt-2 border border-gray-700">
        <h2 className="text-lg font-bold text-center text-white mt-2">
          Ajoutez un multimedia
        </h2>
        <img
          className="w-12 h-12 mx-auto"
          src="/icons/Plus.svg"
          alt="Ajouter un multimedia"
        />
        <p className="text-sm text-center text-white">
          (.JPG, .PNG, .MP4, .MP3, .GIF)
        </p>
      </div>
      <div className="grid grid-cols-2 gap-2 text-center mt-4">
        <div className="bg-gray-800 p-2 rounded-lg border border-gray-700">
          Reponse 1
        </div>
        <div className="bg-gray-800 p-2 rounded-lg border border-gray-700">
          Reponse 2
        </div>
        <div className="bg-gray-800 p-2 rounded-lg border border-gray-700">
          Reponse 3
        </div>
        <div className="bg-gray-800 p-2 rounded-lg border border-gray-700">
          Reponse 4
        </div>
        <div className="col-span-2">
          <img
            className="w-12 h-12 mx-auto"
            src="/icons/Plus.svg"
            alt="Ajouter une reponse"
          />
        </div>
      </div>
      <div className="flex overflow-x-auto flex-nowrap bg-gray-800 p-2 rounded-lg border border-gray-700 mt-4 gap-2">
        <div className="border border-gray-700 rounded-lg flex-shrink-0 w-20 h-20 overflow-hidden">
          <img
            className="w-full h-full object-cover"
            src="/images/natation.jpg"
            alt="Ajouter une reponse image"
          />
        </div>
        <div className="border border-gray-700 rounded-lg flex-shrink-0 w-20 h-20 overflow-hidden">
          <img
            className="w-full h-full object-cover"
            src="/images/argent.jpg"
            alt="Ajouter une reponse image"
          />
        </div>
        <div className="border border-gray-700 rounded-lg flex-shrink-0 w-20 h-20 overflow-hidden">
          <img
            className="w-full h-full object-cover"
            src="/images/husky.jpg"
            alt="Ajouter une reponse image"
          />
        </div>
        <div className="border border-gray-700 rounded-lg flex-shrink-0 w-20 h-20 overflow-hidden flex items-center justify-center bg-gray-700">
          <img
            className="w-10 h-10"
            src="/icons/Plus.svg"
            alt="Ajouter une reponse image"
          />
        </div>
      </div>
    </div>
  );
}   